#ifndef NFv5_HPP_32900409F598C7C9384F3EF9DE2E6FEFDFFEC2DE7A343DDF555DA46BAF873DD3
#define NFv5_HPP_32900409F598C7C9384F3EF9DE2E6FEFDFFEC2DE7A343DDF555DA46BAF873DD3

// see the spec
// https://netflow.caligare.com/netflow_5.htm

#include <netinet/in.h>
#include <stdint.h>

namespace nf5 {

static constexpr size_t MAX_FLOWS = 30;

inline uint16_t hton(uint16_t host) {
	return htons(host);
}

inline uint32_t hton(uint32_t host) {
	return htonl(host);
}

struct [[gnu::packed]] header_wire {
	uint16_t version           = 5;
	uint16_t count;
	uint32_t sys_uptime;
	uint32_t unix_secs;
	uint32_t unix_nsecs;
	uint32_t flow_sequence;
	uint8_t  engine_type       = 0; // fixed 0
	uint8_t  engine_id         = 0; // fixed 0
	uint16_t sampling_interval = 0; // fixed 0

	void finalize() {
		version       = hton(version);
		count         = hton(count);
		sys_uptime    = hton(sys_uptime);
		unix_secs     = hton(unix_secs);
		unix_nsecs    = hton(unix_nsecs);
		flow_sequence = hton(flow_sequence);
	}
};

struct [[gnu::packed]] flow_wire {
	in_addr_t srcaddr;         // network byte order from source
	in_addr_t dstaddr;         // network byte order from source
	uint32_t  nexthop     = 0; // fixed 0
	uint16_t  input       = 0; // fixed 0
	uint16_t  output      = 0; // fixed 0
	uint32_t  pkts        = 0;
	uint32_t  octets      = 0;
	uint32_t  first_time;
	uint32_t  last_time;
	uint16_t  srcport;         // network byte order from source
	uint16_t  dstport;         // network byte order from source
	uint8_t   pad1        = 0; // fixed 0
	uint8_t   tcp_flags   = 0;
	uint8_t   prot        = 6; // TCP; see /etc/protocols
	uint8_t   tos;
	uint16_t  src_as      = 0; // fixed 0
	uint16_t  dst_as      = 0; // fixed 0
	uint8_t   src_mask    = 0; // fixed 0
	uint8_t   dst_mask    = 0; // fixed 0
	uint16_t  pad2        = 0; // fixed 0

	void finalize() {
		pkts       = hton(pkts);
		octets     = hton(octets);
		first_time = hton(first_time);
		last_time  = hton(last_time);
	}
};

// ensure padding doesn't break anything - the structs must be densely packed
static_assert(sizeof(flow_wire) == 48);
static_assert(sizeof(header_wire) == 24);
static_assert(sizeof(in_addr_t) == 4);

} // namespace nf5

#endif
