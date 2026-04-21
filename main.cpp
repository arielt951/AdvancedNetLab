#include <WinSock2.h>
#include <iostream>

#include "NetlabTAU/include/L5/L5.h"
#include "NetlabTAU/include/L4/L4.h"
#include "NetlabTAU/include/L3/L3_impl.h"
#include "NetlabTAU/include/L2/L2.h"
#include "NetlabTAU/include/L1/NIC.h"

#include "NetlabTAU/include/L2/L2_ARP.h"

/* Virtual cable function - defined in L2_impl.cpp */
extern void L2_impl_set_peers(L2_impl* a, L2_impl* b);

/* Collapse namespaces */
using namespace std;
using namespace Tins;

void main(int argc, char *argv[]) {

	/* Declaring the client */
	inet_os inet_client = inet_os();
	NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, nullptr, true, "");

	/* Declaring the client's datalink layer */
	L2_impl datalink_client(inet_client);
	inet_client.datalink(&datalink_client);
	inet_client.arp(new L2_ARP_impl(inet_client));

	// Setting up the client.
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();

	/* Setting up the client's transport layer */
	L4 ICMP_client(true, inet_client);
	inet_client.setICMP(&ICMP_client);

	/* ====================================================================== */

	/* Declaring the server */
	inet_os inet_server = inet_os();
	NIC nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, nullptr, true, "");

	/* Declaring the server's datalink layer */
	L2_impl datalink_server(inet_server);
	inet_server.datalink(&datalink_server);
	inet_server.arp(new L2_ARP_impl(inet_server));

	// Setting up the server.
	inet_server.inetsw(new L3_impl(inet_server, 0, 0, 0), protosw::SWPROTO_IP);
	inet_server.inetsw(new L3_impl(inet_server, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_server.domaininit();

	/* Setting up the server's transport layer */
	L4 ICMP_server(true, inet_server);
	inet_server.setICMP(&ICMP_server);

	/* ====================================================================== */

	/* Pre-populate ARP tables so client and server know each other's MAC */
	inet_client.arp()->insertPermanent(inet_addr("10.0.0.10"), "aa:aa:aa:aa:aa:aa");
	inet_server.arp()->insertPermanent(inet_addr("10.0.0.15"), "bb:bb:bb:bb:bb:bb");

	/* Establish virtual cable between the two datalilinks */
	L2_impl_set_peers(&datalink_client, &datalink_server);

	// Sniffer spawning.
	inet_client.connect(0U);
	inet_server.connect(0U);

    const char* test = "NetlabPingPongTest";
	size_t testlen = string(test).length();

	/* Interactive testing environment mapping */
	string dstip = "10.0.0.10";
	std::cout << "\n===============================" << std::endl;
	std::cout << "[*] Sending ICMP ECHO_REQUEST to " << dstip << std::endl;
	std::cout << "===============================\n" << std::endl;

	/* L4 tries to resolves destination ip address, if it can't it passes null string to L3.*/
	ICMP_client.sendToL4((byte *)test, testlen, dstip, "", ICMP::Flags::ECHO_REQUEST);

	std::string input;

	while (1) {

		std::cout << "Press ENTER to quit: \n\n";
		getline(std::cin, input);
		if (input.empty()) {
			std::cout << "Terminating the loop..." << std::endl;
			break;
		}
	}
}