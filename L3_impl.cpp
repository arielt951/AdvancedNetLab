#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <iomanip>
#include <algorithm>

#include "NetlabTAU/include/L4/L4.h"
#include "NetlabTAU/include/L3/L3_impl.h"
#include <iostream>
#include "NetlabTAU/include/L2/L2.h"
#include "NetlabTAU/include/L1/NIC.h"

/************************************************************************/
/*                         L3_impl				                        */
/************************************************************************/

/* Tips: 
		1. To access the inet's src IP address, use inet.nic().ip_addr
		2. To access the inet's subnetmask address, use inet.nic()._netmask_addr
		3. To access the inet's default gateway address, use inet.nic()._dgw_addr
*/

L3_impl::L3_impl(class inet_os &inet, const short &pr_type, const short &pr_protocol, const short &pr_flags)
	: L3(inet, pr_type, pr_protocol, pr_flags) { }

// Implementation is given to you, do not change - implement ip_output yourself.
int L3_impl::pr_output(const struct pr_output_args& args) { return ip_output(*reinterpret_cast<const struct ip_output_args*>(&args)); };

void L3_impl::pr_init() {
	// INSERT IMPLEMENTATION HERE
}

void L3_impl::pr_input(const struct pr_input_args &args) {

	std::shared_ptr<std::vector<byte>>& m(args.m); // The packet - a vector of bytes.
	std::vector<byte>::iterator& it(args.it); // Iterator to the current position in the packet.
	int hlen = 0; // The header length - calculate it.
    struct iphdr* ip = nullptr; // The IP header - cast the iterator to this type.

	// INSERT IMPLEMENTATION BELOW
	/*****************************/
	
	/* Extract the IP header - iterator already points past the Ethernet header */
	ip = reinterpret_cast<struct iphdr*>(&(*it));
	std::cout << "[L3] <-- pr_input captured frame! Checking ip properties..." << std::endl;
	
	/* 1. Validate IP version is 4 */
	if (ip->ip_v_hl.hb != 4) {
		std::cout << "[L3]     DROPPED: IP version = " << (int)ip->ip_v_hl.hb << " (expected 4)" << std::endl;
		return;
	}
	
	/* 2. Validate Header Length (at least 20 bytes) */
	hlen = ip->ip_v_hl.lb << 2;  
	if (hlen < sizeof(struct iphdr)) {
		std::cout << "[L3]     DROPPED: header length = " << hlen << " (min " << sizeof(struct iphdr) << ")" << std::endl;
		return;
	}
	
	/* 3. Validate Total Length */
	if (ntohs(ip->ip_len) < hlen) {
		std::cout << "[L3]     DROPPED: total length " << ntohs(ip->ip_len) << " < hlen " << hlen << std::endl;
		return;
	}
	
	/* 4. Checksum verification */
	if (in_cksum(&(*it), hlen) != 0) {
		std::cout << "[L3]     DROPPED: bad checksum" << std::endl;
		return;
	}

	/* 5. Verify the protocol is ICMP */
	if (ip->ip_p != IPPROTO_ICMP) {
		std::cout << "[L3]     DROPPED: protocol = " << (int)ip->ip_p << " (not ICMP)" << std::endl;
		return;
	}

	/* 6. Verify destination IP matches our NIC's IP or broadcast */
	std::string src_str = inet_ntoa(ip->ip_src);
	std::string dst_str = inet_ntoa(ip->ip_dst);
	std::string our_str = inet_ntoa(inet.nic()->ip_addr());
	std::cout << "[L3]     src=" << src_str << " dst=" << dst_str 
	          << " our_ip=" << our_str << std::endl;
	if (ip->ip_dst.s_addr != inet.nic()->ip_addr().s_addr && ip->ip_dst.s_addr != 0xFFFFFFFF) {
		std::cout << "[L3]     DROPPED: destination IP mismatch" << std::endl;
		return;
	}
	std::cout << "[L3]     ACCEPTED! Passing to L4..." << std::endl;

	/* Advance iterator past the IP header */
	it += hlen;
	
	


	
	/*****************************/
	// INSERT IMPLEMENTATION ABOVE

	// Connect to L4.
	if (ip->ip_p == IPPROTO_ICMP) {
		byte* sendData = m->data() + sizeof(L2::ether_header) + sizeof(iphdr);
		size_t sendDataLen = m->size() - sizeof(L2::ether_header) - sizeof(iphdr);
        std::string destIP = std::string(inet_ntoa(ip->ip_src));
		inet.getICMP()->recvFromL4(sendData, sendDataLen, destIP);
		return;
	}
}

int L3_impl::ip_output(const struct ip_output_args &args) {
	std::shared_ptr<std::vector<byte>>& m = args.m;
	std::vector<byte>::iterator& it = args.it;
	
	/* Position iterator at the start of the IP header space (after L2 header) */
	it = m->begin() + sizeof(L2::ether_header);
	
	struct iphdr* ip = reinterpret_cast<struct iphdr*>(&(*it));
	std::cout << "[L3] --> ip_output initiated. Wrapping IP encapsulation..." << std::endl;
	int hlen = sizeof(struct iphdr);

	/* Fill the IP header fields */
	ip->ip_v_hl.hb = 4;                      /* IPv4 */
	ip->ip_v_hl.lb = hlen >> 2;              /* Header length in 32-bit words */
	ip->ip_tos = 0;                          /* Type of Service */
	ip->ip_len = htons(m->size() - sizeof(L2::ether_header)); /* Total size of IP packet */
	ip->ip_id = htons(++ip_id);              /* Packet ID */
	ip->ip_off = 0;                          /* No fragmentation */
	ip->ip_ttl = 64;                         /* TTL default */
	ip->ip_p = IPPROTO_ICMP;                 /* Protocol (ICMP) */
	ip->ip_sum = 0;                          /* Zero checksum before calculation */
	ip->ip_src = inet.nic()->ip_addr();       /* Source IP is our NIC's IP */
	
	/* Extract Destination IP from routing information */
	struct sockaddr_in* dst_in = reinterpret_cast<struct sockaddr_in*>(&args.ro->ro_dst);
	ip->ip_dst = dst_in->sin_addr;

	/* Compute checksum over the header length */
	ip->ip_sum = in_cksum(&(*it), hlen);

	/* Routing: if destination is NOT in our subnet, redirect L2 next-hop to gateway */
	if (args.ro) {
		struct sockaddr_in* ro_dst_in = reinterpret_cast<struct sockaddr_in*>(&(args.ro->ro_dst));
		
		uint32_t target_ip = ro_dst_in->sin_addr.s_addr;
		uint32_t my_ip = inet.nic()->ip_addr().s_addr;
		uint32_t mask = inet.nic()->netmask_addr().s_addr;

		if ((target_ip & mask) != (my_ip & mask)) {
			/* External: next hop is the default gateway */
			ro_dst_in->sin_addr.s_addr = inet.nic()->dgw_addr().s_addr;
			std::cout << "[L3]     External target -> routing via gateway" << std::endl;
		} else {
			std::cout << "[L3]     Internal target -> direct routing" << std::endl;
		}
	}

	/* Pass down to Layer 2 (Data Link) */
	inet.datalink()->ether_output(m, it, &(args.ro->ro_dst), args.ro->ro_rt);
	return 0;
}