#include <iomanip>
#include <string>

#include "NetlabTAU/include/L3/L3.h"
#include "NetlabTAU/include/L2/L2.h"
#include "NetlabTAU/include/L2/L2_ARP.h"
#include "NetlabTAU/include/L1/NIC.h"

/************************************************************************/
/*                         L2			                                */
/************************************************************************/

L2::L2(class inet_os &inet) : inet(inet) { inet.datalink(this); }

L2::~L2() { inet.datalink(nullptr); }

/************************************************************************/
/*                   Virtual Cable (peer routing)                       */
/************************************************************************/

/*
 * Global peer map: when ether_output sends a frame, it also delivers
 * a copy directly to the peer L2_impl's ether_input. This bypasses
 * pcap loopback, which doesn't work on Wi-Fi adapters in Windows.
 */
static L2_impl* g_peer_a = nullptr;
static L2_impl* g_peer_b = nullptr;

void L2_impl_set_peers(L2_impl* a, L2_impl* b) {
	g_peer_a = a;
	g_peer_b = b;
}

static L2_impl* get_peer(L2_impl* self) {
	if (self == g_peer_a) return g_peer_b;
	if (self == g_peer_b) return g_peer_a;
	return nullptr;
}

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
	
	std::cout << "[L2] <-- ether_input captured frame! EtherType: 0x" << std::hex << ether_type << std::dec << std::endl;

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
		/* Unknown ether_type - drop the packet */
		break;
	}
}

void L2_impl::ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt0) 
{
	L2::ether_header *eh;
	mac_addr desten;       /* destination MAC address */
	u_short ether_type = 0;
	std::cout << "[L2] --> ether_output initiated. Routing frame down to NIC..." << std::endl;
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

	/* Always send via L1/NIC so Wireshark can capture the frame */
	inet.nic()->lestart(m, it);

	/* Virtual cable: also deliver directly to the peer's ether_input.
	 * This ensures reliable delivery even when pcap loopback doesn't work. */
	L2_impl* peer = get_peer(this);
	if (peer) {
		/* Make a copy of the frame for the peer */
		auto m_copy = std::make_shared<std::vector<byte>>(*m);
		auto it_copy = m_copy->begin();

		/* The ether_header in the copy has ether_type in WIRE (network) byte order.
		 * The framework's leread normally converts to host byte order before calling ether_input.
		 * We must do the same conversion here. */
		L2::ether_header* eh_copy = reinterpret_cast<L2::ether_header*>(&(*it_copy));
		eh_copy->ether_type = ntohs(eh_copy->ether_type);

		/* Advance iterator past the Ethernet header (this is what leread does) */
		it_copy += sizeof(L2::ether_header);

		peer->ether_input(m_copy, it_copy, eh_copy);
	}
}