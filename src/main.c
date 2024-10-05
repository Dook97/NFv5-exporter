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

#include "utils.h"

typedef struct {
	char *pcapf;
	char *host;
	int  port;
	int  atimeout;
	int  itimeout;
} args_t;

#define HSEP "    "

#define USAGE \
	"USAGE: p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout>] [-h]"

#define OPTS_DESC                                                                      \
	HSEP"<host:port>     "HSEP"Socket address of a running NetFlow v5 collector\n" \
	HSEP"<pcap_file_path>"HSEP"The pcap file to be processed\n"                    \
	HSEP"-a UINT         "HSEP"Active timeout (optional; default 60)\n"            \
	HSEP"-i UINT         "HSEP"Inactive timeout (optional; default 60)\n"          \
	HSEP"-h              "HSEP"This help"

int parse_args(int argc, char **argv, args_t *out_args) {
	*out_args = (args_t){
		.atimeout = 60,
		.itimeout = 60,
	};

	for (char opt; (opt = getopt(argc, argv, "a:i:h")) != -1;) {
		switch (opt) {
		case 'a':
			out_args->atimeout = stoi(optarg);
			break;
		case 'i':
			out_args->itimeout = stoi(optarg);
			break;
		case 'h':
			fprintf(stderr, USAGE"\n\nOPTONS\n"OPTS_DESC"\n");
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

	const char *strport = sep + 1;
	if ((out_args->port = stoi(strport)) == INT_MIN) {
		fprintf(stderr, "port argument not a number");
		return 1;
	}

	out_args->pcapf = argv[++optind];

	return 0;
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
	DPRINTF("port:         %d\n", args.port);
	DPRINTF("active:       %d\n", args.atimeout);
	DPRINTF("inactive:     %d\n", args.itimeout);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcf = pcap_open_offline(args.pcapf, errbuf);
	if (pcf == NULL) {
		fprintf(stderr, "couldn't open capture file: %s\n", errbuf);
		exit(1);
	}
}
