#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <bitset>
#include <iostream>

#include "NetlabTAU/include/L4/L4.h"
#include "NetlabTAU/include/L3/L3_impl.h"
#include "NetlabTAU/include/L2/L2.h"
#include "NetlabTAU/include/L1/NIC.h"
#include "NetlabTAU/include/infra/Print.h"

#define ICMP_HEADER 8 // ICMP header size - hint: use this inside recvFromL4.

/* Collapse namespaces */
using namespace std;
using namespace netlab;

/************************************************************************/
/*                         L4_ICMP_impl				                    */
/************************************************************************/

L3_impl::ip_output_args::ip_output_args(std::shared_ptr<std::vector<byte>>& m, std::vector<byte>::iterator& it,
	std::shared_ptr<std::vector<byte>>& opt, struct L3::route* ro, int flags, struct  L3::ip_moptions* imo)
	: m(m), it(it), opt(opt), ro(ro), flags(flags), imo(imo) { }

L4::L4(bool debug, class inet_os& inet) : debug(debug), inet(inet), recvPacketLen(0), recvPacket(NULL)
{
	pthread_mutex_init(&recvPacket_mutex, NULL);
	pthread_mutex_lock(&recvPacket_mutex);
}

L3* L4::getNetworkLayer() { return reinterpret_cast<L3*>(inet.inetsw(protosw::SWPROTO_IP_RAW)); }

int L4::sendToL4(byte *sendData, size_t sendDataLen, std::string destIP, std::string srcIP, Tins::ICMP::Flags flag)
{
	try {
		std::cout << "[L4] --> sendToL4 initiated! Constructing ICMP payload for IP: " << destIP << std::endl;
		// 1. Build the ICMP segment with libtins
		Tins::ICMP icmp(flag); 
		Tins::RawPDU payload(sendData, sendDataLen);
		icmp /= payload; // Tins overrides the `/=` to concatenate PDUs

		// 2. Serialize the ICMP segment 
		std::vector<uint8_t> buffer = icmp.serialize();

		// 3. Allocate full packet vector (L2 header size + L3 header size + ICMP block size)
		size_t full_size = sizeof(L2::ether_header) + sizeof(L3::iphdr) + buffer.size();
		std::shared_ptr<std::vector<byte>> m = std::make_shared<std::vector<byte>>(full_size);

		// 4. Inject Serialized ICMP into the buffer
		std::copy(buffer.begin(), buffer.end(), m->begin() + sizeof(L2::ether_header) + sizeof(L3::iphdr));

		// 5. Structure Route configurations and `ip_output_args` config
		char route_buf[sizeof(L3::route)] = {0}; // Bypass linking the unimplemented constructor
		L3::route* ro = reinterpret_cast<L3::route*>(route_buf);
		
		struct sockaddr_in* dest_addr = reinterpret_cast<struct sockaddr_in*>(&ro->ro_dst);
		dest_addr->sin_family = AF_INET;
		dest_addr->sin_addr.s_addr = inet_addr(destIP.c_str());
		
		std::vector<byte>::iterator it = m->begin() + sizeof(L2::ether_header) + sizeof(L3::iphdr);
		std::shared_ptr<std::vector<byte>> opt(nullptr);
		
		L3_impl::ip_output_args args(m, it, opt, ro, 0, nullptr);
		
		// 6. Push down to Network Layer
		return getNetworkLayer()->pr_output(args);

	} catch (const std::exception& e) {
		std::cerr << "L4 Send Exception: " << e.what() << std::endl;
		return -1;
	}
}

/*** Tip: To access the inet's src IP address, use inet.nic().ip_addr ***/

int L4::recvFromL4(byte* sendData, size_t sendDataLen, std::string destIP)
{	
	try {
		std::cout << "[L4] <-- recvFromL4 unwrapping packet!" << std::endl;
		// 1. Unwrap ICMP packet 
		Tins::ICMP icmp(sendData, sendDataLen);

		// 2. Validate Type (It must be an ECHO request or ECHO reply)
		if (icmp.type() != Tins::ICMP::ECHO_REPLY && icmp.type() != Tins::ICMP::ECHO_REQUEST) {
			std::cout << "[L4]     Packet is not target ECHO class (dropped)." << std::endl;
			return 0; // Drop irrelevant traffic
		}

		// 3. Extract Raw Payload Payload	
		const Tins::RawPDU* raw = icmp.find_pdu<Tins::RawPDU>();
		if (raw) {
			std::vector<uint8_t> payload = raw->payload();
			
			// Overwrite historical buffer segment safely
			if (recvPacket) {
				delete[] recvPacket;
			}

			recvPacketLen = payload.size();
			recvPacket = new byte[recvPacketLen];
			std::copy(payload.begin(), payload.end(), recvPacket);

			if (icmp.type() == Tins::ICMP::ECHO_REQUEST) {
				std::cout << "[L4]     Captured ECHO_REQUEST! Sending ECHO_REPLY back to " << destIP << "..." << std::endl;
				sendToL4(recvPacket, recvPacketLen, destIP, "", Tins::ICMP::ECHO_REPLY);
			}

			// 4. Temporarily unlock thread sync mechanisms to allow reading processes to catch it
			pthread_mutex_unlock(&recvPacket_mutex);
			Sleep(10);
			pthread_mutex_lock(&recvPacket_mutex);

			return sendDataLen;
		}
	} catch (const Tins::malformed_packet&) {
		// Drop silently if sizes don't match the required Tins footprint
		return 0;
	}

	return 0;
}

L4::~L4()
{
	pthread_mutex_destroy(&recvPacket_mutex);	/* Free up the_mutex */
	if (recvPacket)
		delete[] recvPacket;
}