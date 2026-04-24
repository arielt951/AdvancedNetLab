#include <iomanip>
#include <string>
#include <chrono>
#include <sstream>

#include "NetlabTAU/include/L3/L3.h"
#include "NetlabTAU/include/L2/L2.h"
#include "NetlabTAU/include/L2/L2_ARP.h"
#include "NetlabTAU/include/L1/NIC.h"

/* Timestamp helper — returns "[HH:MM:SS.mmm]" */
static std::string ts() {
	auto now = std::chrono::system_clock::now();
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
	auto t = std::chrono::system_clock::to_time_t(now);
	struct tm tm_buf;
	localtime_s(&tm_buf, &t);
	std::ostringstream oss;
	oss << "[" << std::setfill('0') << std::setw(2) << tm_buf.tm_hour
	    << ":" << std::setw(2) << tm_buf.tm_min
	    << ":" << std::setw(2) << tm_buf.tm_sec
	    << "." << std::setw(3) << ms.count() << "] ";
	return oss.str();
}

/************************************************************************/
/*                         L2			                                */
/************************************************************************/

L2::L2(class inet_os &inet) : inet(inet) { inet.datalink(this); }

L2::~L2() { inet.datalink(nullptr); }

/************************************************************************/
/*                         L2_impl		                                */
/************************************************************************/

/*** Tip: To access the inet's src mac address, use inet.nic().mac ***/

L2_impl::L2_impl(class inet_os &inet) : L2(inet) { }

void L2_impl::ether_input(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct ether_header *eh) {
	/* Get the ether_type (framework provides it in host byte order) */
	u_short ether_type = eh->ether_type;
	
	/* Prevent self-loop: drop frames that came from our own MAC (pcap reflection) */
	if (eh->ether_shost == inet.nic()->mac()) {
		return;
	}

	/* Demultiplex based on Ethernet type field */
	switch (ether_type) {
	case L2::ether_header::ETHERTYPE_IP:
	{
		/* IP packet - pass up to L3 (IP layer) */
		protosw *ip_proto = inet.inetsw(protosw::SWPROTO_IP);
		if (ip_proto) {
			int iphlen = 0;
			protosw::pr_input_args args(m, it, iphlen);
			ip_proto->pr_input(args);
		}
		break;
	}
	case L2::ether_header::ETHERTYPE_ARP:
	{
		/* ARP packet - pass to ARP module */
		if (inet.arp())
			inet.arp()->in_arpinput(m, it);
		break;
	}
	default:
		/* Unknown ether_type - drop the packet silently */
		break;
	}
}

void L2_impl::ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt0) 
{
	L2::ether_header *eh;
	mac_addr desten;       /* destination MAC address */
	u_short ether_type = 0;
	std::cout << ts() << "[L2] --> ether_output initiated. Routing frame down to NIC..." << std::endl;
	//Extractions of the fields according to the packet type (IP or ARP) and the address family in dst
	if (dst->sa_family == AF_INET) {
		/* Normal IP packet - resolve destination IP to MAC via ARP */
		if (inet.arp() == nullptr) {
			return; /* Drop packet if ARP is not configured */
		}
		mac_addr *resolved = inet.arp()->arpresolve(m, it, 0, dst);
		if (resolved == nullptr)
			return;  /* ARP is holding the packet until resolution completes */
		desten = *resolved;
		ether_type = htons(L2::ether_header::ETHERTYPE_IP);
	}
	else if (dst->sa_family == AF_UNSPEC) {
		/* Pre-built Ethernet header (used by ARP to avoid infinite loop) */
		eh = reinterpret_cast<L2::ether_header*>(dst->sa_data);
		desten = eh->ether_dhost;
		ether_type = eh->ether_type;
	}
	else {
		return;  /* Unsupported address family */
	}

	/* Write the Ethernet header at the beginning of the packet buffer */
	it = m->begin();
	eh = reinterpret_cast<L2::ether_header*>(&(*it));
	eh->ether_dhost = desten; //extracted destination mac address from above
	eh->ether_shost = inet.nic()->mac(); //accesing our nic to get the source mac address
	eh->ether_type = ether_type; //extracted ether_type from above

	/* Zero-pad to minimum Ethernet frame size (60 bytes total, 46 bytes data) */
	size_t data_len = m->size() - sizeof(L2::ether_header);
	if (data_len < ETHERMIN) {
		m->resize(sizeof(L2::ether_header) + ETHERMIN, 0);  /* pad with zeros */
		it = m->begin(); /* Re-assign iterator invalidated by resize */
	}

	/* Send via L1/NIC — frame goes onto the real network adapter */
	inet.nic()->lestart(m, it);
}