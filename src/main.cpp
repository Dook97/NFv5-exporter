#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define __USE_MISC 1
#include <sys/types.h>
#undef __USE_MISC
#include <pcap/pcap.h>

#include "utils.hpp"

typedef struct {
	char *pcapf;
	char *host;
	char *port;
	int  atimeout;
	int  itimeout;
	int  sock;
} args_t;

#define HSEP "    "

#define USAGE \
	"USAGE: p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout>] [-h]"

#define OPTS_DESC                                                                         \
	HSEP "<host:port>     " HSEP "Socket address of a running NetFlow v5 collector\n" \
	HSEP "<pcap_file_path>" HSEP "The pcap file to be processed\n"                    \
	HSEP "-a UINT         " HSEP "Active timeout (optional; default 60)\n"            \
	HSEP "-i UINT         " HSEP "Inactive timeout (optional; default 60)\n"          \
	HSEP "-h              " HSEP "This help"

int parse_args(int argc, char **argv, args_t *out_args) {
	out_args->atimeout = 60;
	out_args->itimeout = 60;

	for (char opt; (opt = getopt(argc, argv, "a:i:h")) != -1;) {
		switch (opt) {
		case 'a':
			out_args->atimeout = stoi(optarg);
			break;
		case 'i':
			out_args->itimeout = stoi(optarg);
			break;
		case 'h':
			fprintf(stderr, USAGE "\n\nOPTONS\n" OPTS_DESC "\n");
			return 0;
		default:
			return 1;
		}
	}

	if (argc - optind != 2) {
		fprintf(stderr, "too %s args\n", (argc - optind < 2) ? "few" : "many");
		return 1;
	}

	char *host = argv[optind];
	char *sep = strchr(host, ':');
	if (sep == NULL) {
		fprintf(stderr, "bad host string format\n");
		return 1;
	}
	*sep = '\0';

	out_args->host = host;
	out_args->port = sep + 1;
	out_args->pcapf = argv[++optind];

	return 0;
}

void pkt_handler(uint8_t *ctx, const struct pcap_pkthdr *phdr, const uint8_t *pkt) {
	printf("%d\n", phdr->caplen);
}

int udp_connect(const char *host, const char *port) {
	int proto_udp = getprotobyname("UDP")->p_proto;
	int sock = socket(AF_INET, SOCK_DGRAM, proto_udp);
	if (sock < 0)
		return -1;

	struct addrinfo *res = NULL;
	struct addrinfo hints;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = proto_udp;
	hints.ai_flags = AI_NUMERICSERV;

	int errn = getaddrinfo(host, port, &hints, &res);
	if (errn) {
		fprintf(stderr, "%s\n", gai_strerror(errn));
		goto err;
	}

	for (struct addrinfo *addr = res; addr != NULL; addr = addr->ai_next) {
		if (connect(sock, addr->ai_addr, addr->ai_addrlen) != -1)
			goto end;
	}

err:
	close(sock);
	sock = -1;
end:
	freeaddrinfo(res);
	return sock;
}

int main(int argc, char **argv) {
	DPRINTF(RED(">>> YOU ARE RUNNING A DEBUG BUILD <<<\n"));

	args_t args;
	if (parse_args(argc, argv, &args)) {
		fprintf(stderr, USAGE"\n");
		exit(1);
	}

	DPRINTF("capture file: %s\n", args.pcapf);
	DPRINTF("host:         %s\n", args.host);
	DPRINTF("port:         %s\n", args.port);
	DPRINTF("active:       %d\n", args.atimeout);
	DPRINTF("inactive:     %d\n", args.itimeout);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcf = pcap_open_offline(args.pcapf, errbuf);
	if (pcf == NULL) {
		fprintf(stderr, "couldn't open capture file: %s\n", errbuf);
		exit(1);
	}

	int ecode = 1;
	args.sock = udp_connect(args.host, args.port);
	if (args.sock < 0) {
		fprintf(stderr, "failed to connect to collector\n");
		goto end;
	}

	if (pcap_loop(pcf, -1, pkt_handler, (uint8_t *)&args) == PCAP_ERROR)
		fprintf(stderr, "%s\n", (pcap_perror(pcf, errbuf), errbuf));
	ecode = 0;

end:
	pcap_close(pcf);
	close(args.sock);
	return ecode;
}
