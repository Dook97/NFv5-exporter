#include <assert.h>
#include <getopt.h>
#include <limits.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tuple>
#include <map>

#include "nfv5.hpp"

#define USAGE \
	"USAGE: p2nprobe <host>:<port> <pcap_file> [-a <active_timeout> -i <inactive_timeout>]"

#define OPTS_DESC                                                                    \
	"OPTIONS\n"                                                                  \
	"    <host>:<port>       Socket address of a running NetFlow v5 collector\n" \
	"    <pcap_file>         The pcap file to be processed\n"                    \
	"    -a UINT             Active timeout (optional; default 60)\n"            \
	"    -i UINT             Inactive timeout (optional; default 60)\n"          \
	"    -h                  This help"

// {addr_src, socket_src, addr_dest, socket_dest}
using fmap_k = std::tuple<in_addr_t, uint16_t, in_addr_t, uint16_t>;
using fmap = std::map<fmap_k, nf5::flow_wire>;

struct export_ctx {
	fmap     flows;
	char     *pcapf;
	char     *host;
	char     *port;
	uint32_t atimeout_ms = 60000;
	uint32_t itimeout_ms = 60000;
	int      sock = -1;
	uint32_t start_ms = 0;
	uint32_t uptime_ms;
	uint32_t unix_s;
	uint32_t unix_ns;
	uint32_t flow_seq = 0;
};

static uint32_t timeval_to_ms(const timeval &tv) {
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

/*! @returns 1 on failure, 0 otherwise */
static int parse_args(int argc, char **argv, export_ctx &out) {
	for (char opt; (opt = getopt(argc, argv, "a:i:h")) != -1;) {
		switch (opt) {
		case 'a':
			out.atimeout_ms = atoi(optarg) * 1000;
			break;
		case 'i':
			out.itimeout_ms = atoi(optarg) * 1000;
			break;
		case 'h':
			fprintf(stderr, USAGE "\n\n" OPTS_DESC "\n");
			exit(0);
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

	out.host = host;
	out.port = sep + 1;
	out.pcapf = argv[++optind];

	return 0;
}

static void export_flows(export_ctx &ctx, uint16_t nflows, nf5::flow_wire *eflows[]) {
	assert(nflows <= nf5::MAX_FLOWS);

	uint8_t buf[sizeof(nf5::header_wire) + nf5::MAX_FLOWS * sizeof(nf5::flow_wire)];

	nf5::header_wire hdr = {
		.count = nflows,
		.sys_uptime = ctx.uptime_ms,
		.unix_secs = ctx.unix_s,
		.unix_nsecs = ctx.unix_ns,
		.flow_sequence = (ctx.flow_seq += nflows),
	};
	hdr.finalize();
	memcpy(buf, &hdr, sizeof(hdr));

	for (size_t i = 0; i < nflows; ++i) {
		nf5::flow_wire &flow = *eflows[i];
		flow.finalize();
		memcpy(&buf[sizeof(hdr) + i * sizeof(flow)], &flow, sizeof(flow));
	}

	size_t msg_size = sizeof(hdr) + nflows * sizeof(nf5::flow_wire);
	send(ctx.sock, buf, msg_size, 0);
}

static void pkt_info_acc(uint8_t *ctx_, const pcap_pkthdr *pchdr, const uint8_t *pkt) {
	static constexpr size_t ETHERNET_HDR_LEN = 14; // wikipedia.org/wiki/Ethernet_frame#Structure

	export_ctx &ctx = *(export_ctx *)ctx_;
	fmap &flows = ctx.flows;

	uint32_t now_ms = timeval_to_ms(pchdr->ts);
	if (ctx.start_ms == 0) // if previously uninitialized
		ctx.start_ms = now_ms;
	ctx.uptime_ms = now_ms - ctx.start_ms;
	ctx.unix_s = pchdr->ts.tv_sec;
	ctx.unix_ns = pchdr->ts.tv_usec * 1000;

	struct ip *ip_h = (struct ip *)&pkt[ETHERNET_HDR_LEN];
	struct tcphdr *tcp_h = (tcphdr *)&pkt[ETHERNET_HDR_LEN + ip_h->ip_hl * 4];

	// sanity check; pcap filter should guarantee this
	assert(ip_h->ip_v == 4);
	assert(ip_h->ip_p == IPPROTO_TCP);

	fmap_k key = {
		ip_h->ip_src.s_addr,
		tcp_h->th_sport,
		ip_h->ip_dst.s_addr,
		tcp_h->th_dport,
	};

	bool new_flow = !flows.contains(key);
	nf5::flow_wire &cur = flows[key]; // subscription operator creates entry if not present
	if (new_flow) {
		cur.srcaddr    = ip_h->ip_src.s_addr;
		cur.dstaddr    = ip_h->ip_dst.s_addr;
		cur.first_time = ctx.uptime_ms;
		cur.srcport    = tcp_h->th_sport;
		cur.dstport    = tcp_h->th_dport;
		cur.tos        = ip_h->ip_tos;
	}
	++cur.pkts;
	cur.octets    += ntohs(ip_h->ip_len);
	cur.last_time  = ctx.uptime_ms;
	cur.tcp_flags |= tcp_h->th_flags;

	// export up to MAX_FLOWS finished or expired flows, then free them from memory
	uint16_t to_send = 0;
	fmap_k flow_keys[nf5::MAX_FLOWS];
	nf5::flow_wire *eflows[nf5::MAX_FLOWS];
	for (auto &&[key, val] : flows) {
		if (ctx.uptime_ms - val.first_time > ctx.atimeout_ms
		    || ctx.uptime_ms - val.last_time > ctx.itimeout_ms
		    || val.tcp_flags & (TH_RST | TH_FIN)) {
			flow_keys[to_send] = key;
			eflows[to_send] = &val;
			if (++to_send >= nf5::MAX_FLOWS)
				break;
		}
	}
	if (to_send > 0)
		export_flows(ctx, to_send, eflows);
	for (size_t i = 0; i < to_send; ++i)
		flows.erase(flow_keys[i]);
}

static int udp_connect(const char *host, const char *port) {
	static constexpr int PROTO_UDP = 17; // see /etc/protocols

	int sock = socket(AF_INET, SOCK_DGRAM, PROTO_UDP);
	if (sock < 0)
		return -1;

	struct addrinfo hints;
	struct addrinfo *res = NULL;
	hints.ai_family   = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = PROTO_UDP;
	hints.ai_flags    = AI_NUMERICSERV;

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

static void export_all(export_ctx &ctx, pcap_t *pcf) {
	pcap_loop(pcf, -1, pkt_info_acc, (uint8_t *)&ctx);

	// export remaining flows
	for (auto it = ctx.flows.begin(); it != ctx.flows.end();) {
		size_t to_send = 0;
		nf5::flow_wire *eflows[nf5::MAX_FLOWS];
		for (size_t i = 0; i < nf5::MAX_FLOWS; ++i) {
			eflows[i] = &it->second;
			++to_send;
			if (++it == ctx.flows.end())
				break;
		}
		export_flows(ctx, to_send, eflows);
	}
}

int main(int argc, char **argv) {
	export_ctx ctx;
	if (parse_args(argc, argv, ctx)) {
		fprintf(stderr, USAGE"\n");
		exit(1);
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcf = pcap_open_offline(ctx.pcapf, errbuf);
	if (pcf == NULL) {
		fprintf(stderr, "couldn't open capture file: %s\n", errbuf);
		exit(1);
	}

	int ecode = 1;

	bpf_program bpfp = {.bf_len = 0, .bf_insns = NULL};
	const char *filter = "ip proto \\tcp"; // only inspect ipv4 tcp packets
	if (pcap_compile(pcf, &bpfp, filter, true, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
		pcap_perror(pcf, errbuf);
		fprintf(stderr, "%s\n", errbuf);
		goto end;
	}

	if (pcap_setfilter(pcf, &bpfp)) {
		fprintf(stderr, "failed to setup pcap filter\n");
		goto end;
	}

	ctx.sock = udp_connect(ctx.host, ctx.port);
	if (ctx.sock < 0) {
		fprintf(stderr, "failed to connect to collector\n");
		goto end;
	}

	export_all(ctx, pcf);

	ecode = 0;

end:
	pcap_freecode(&bpfp);
	close(ctx.sock);
	pcap_close(pcf);
	return ecode;
}
