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

/************************************************************************/
/* Scenario A: Send ICMP REQUEST to external IP (NOT in our subnet)     */
/*   Client (10.0.0.15/24) pings Server (20.0.0.10/24) via gateway     */
/************************************************************************/
void testExternal() {
	const char* test = "NetlabPingPongTest";
	size_t testlen = string(test).length();

	/* Client: 10.0.0.15/24, gateway 10.0.0.1 */
	inet_os inet_client = inet_os();
	NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", "10.0.0.1", "255.255.255.0", true, "");

	L2_impl datalink_client(inet_client);
	inet_client.datalink(&datalink_client);
	inet_client.arp(new L2_ARP_impl(inet_client));
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	L4 ICMP_client(true, inet_client);
	inet_client.setICMP(&ICMP_client);

	/* Server: 20.0.0.10/24, gateway 20.0.0.1 (for reply routing back) */
	inet_os inet_server = inet_os();
	NIC nic_server(inet_server, "20.0.0.10", "aa:aa:aa:aa:aa:aa", "20.0.0.1", "255.255.255.0", true, "");

	L2_impl datalink_server(inet_server);
	inet_server.datalink(&datalink_server);
	inet_server.arp(new L2_ARP_impl(inet_server));
	inet_server.inetsw(new L3_impl(inet_server, 0, 0, 0), protosw::SWPROTO_IP);
	inet_server.inetsw(new L3_impl(inet_server, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_server.domaininit();
	L4 ICMP_server(true, inet_server);
	inet_server.setICMP(&ICMP_server);

	/* ARP tables:
	 * Client: gateway 10.0.0.1 -> server's MAC (frame reaches server's NIC)
	 * Server: gateway 20.0.0.1 -> client's MAC (reply reaches client's NIC) */
	inet_client.arp()->insertPermanent(inet_addr("10.0.0.1"), "aa:aa:aa:aa:aa:aa");
	inet_server.arp()->insertPermanent(inet_addr("20.0.0.1"), "bb:bb:bb:bb:bb:bb");

	/* Virtual cable + sniffer */
	L2_impl_set_peers(&datalink_client, &datalink_server);
	inet_client.connect(0U);
	inet_server.connect(0U);

	std::cout << "\n===============================" << std::endl;
	std::cout << "[*] SCENARIO A: External Ping" << std::endl;
	std::cout << "[*] Client 10.0.0.15 --> Server 20.0.0.10 (via gateway 10.0.0.1)" << std::endl;
	std::cout << "===============================\n" << std::endl;

	ICMP_client.sendToL4((byte *)test, testlen, "20.0.0.10", "", ICMP::Flags::ECHO_REQUEST);

	std::string input;
	std::cout << "\nPress ENTER to quit: ";
	getline(std::cin, input);
}

/************************************************************************/
/* Scenario B: Send ICMP REQUEST to IP IN our subnet (direct)           */
/*   Client (10.0.0.15/24) pings Server (10.0.0.10/24) directly        */
/************************************************************************/
void testInternal() {
	const char* test = "NetlabPingPongTest";
	size_t testlen = string(test).length();

	/* Client: 10.0.0.15/24 */
	inet_os inet_client = inet_os();
	NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, "255.255.255.0", true, "");

	L2_impl datalink_client(inet_client);
	inet_client.datalink(&datalink_client);
	inet_client.arp(new L2_ARP_impl(inet_client));
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	L4 ICMP_client(true, inet_client);
	inet_client.setICMP(&ICMP_client);

	/* Server: 10.0.0.10/24 (same subnet) */
	inet_os inet_server = inet_os();
	NIC nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, "255.255.255.0", true, "");

	L2_impl datalink_server(inet_server);
	inet_server.datalink(&datalink_server);
	inet_server.arp(new L2_ARP_impl(inet_server));
	inet_server.inetsw(new L3_impl(inet_server, 0, 0, 0), protosw::SWPROTO_IP);
	inet_server.inetsw(new L3_impl(inet_server, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_server.domaininit();
	L4 ICMP_server(true, inet_server);
	inet_server.setICMP(&ICMP_server);

	/* ARP: direct MAC resolution (same subnet, no gateway needed) */
	inet_client.arp()->insertPermanent(inet_addr("10.0.0.10"), "aa:aa:aa:aa:aa:aa");
	inet_server.arp()->insertPermanent(inet_addr("10.0.0.15"), "bb:bb:bb:bb:bb:bb");

	/* Virtual cable + sniffer */
	L2_impl_set_peers(&datalink_client, &datalink_server);
	inet_client.connect(0U);
	inet_server.connect(0U);

	std::cout << "\n===============================" << std::endl;
	std::cout << "[*] SCENARIO B: Internal Ping (same subnet)" << std::endl;
	std::cout << "[*] Client 10.0.0.15 --> Server 10.0.0.10 (direct)" << std::endl;
	std::cout << "===============================\n" << std::endl;

	ICMP_client.sendToL4((byte *)test, testlen, "10.0.0.10", "", ICMP::Flags::ECHO_REQUEST);

	std::string input;
	std::cout << "\nPress ENTER to quit: ";
	getline(std::cin, input);
}

/************************************************************************/
/* Scenario C: Receive ICMP REQUEST from IP in our subnet, send reply   */
/*   Server (10.0.0.10/24) pings Client (10.0.0.15/24)                 */
/*   Client automatically sends ECHO_REPLY back                        */
/************************************************************************/
void testReceive() {
	const char* test = "NetlabPingPongTest";
	size_t testlen = string(test).length();

	/* Client: 10.0.0.15/24 — this time CLIENT is the one receiving */
	inet_os inet_client = inet_os();
	NIC nic_client(inet_client, "10.0.0.15", "bb:bb:bb:bb:bb:bb", nullptr, "255.255.255.0", true, "");

	L2_impl datalink_client(inet_client);
	inet_client.datalink(&datalink_client);
	inet_client.arp(new L2_ARP_impl(inet_client));
	inet_client.inetsw(new L3_impl(inet_client, 0, 0, 0), protosw::SWPROTO_IP);
	inet_client.inetsw(new L3_impl(inet_client, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_client.domaininit();
	L4 ICMP_client(true, inet_client);
	inet_client.setICMP(&ICMP_client);

	/* Server: 10.0.0.10/24 — this time SERVER initiates the ping */
	inet_os inet_server = inet_os();
	NIC nic_server(inet_server, "10.0.0.10", "aa:aa:aa:aa:aa:aa", nullptr, "255.255.255.0", true, "");

	L2_impl datalink_server(inet_server);
	inet_server.datalink(&datalink_server);
	inet_server.arp(new L2_ARP_impl(inet_server));
	inet_server.inetsw(new L3_impl(inet_server, 0, 0, 0), protosw::SWPROTO_IP);
	inet_server.inetsw(new L3_impl(inet_server, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet_server.domaininit();
	L4 ICMP_server(true, inet_server);
	inet_server.setICMP(&ICMP_server);

	/* ARP: direct MAC resolution */
	inet_client.arp()->insertPermanent(inet_addr("10.0.0.10"), "aa:aa:aa:aa:aa:aa");
	inet_server.arp()->insertPermanent(inet_addr("10.0.0.15"), "bb:bb:bb:bb:bb:bb");

	/* Virtual cable + sniffer */
	L2_impl_set_peers(&datalink_client, &datalink_server);
	inet_client.connect(0U);
	inet_server.connect(0U);

	std::cout << "\n===============================" << std::endl;
	std::cout << "[*] SCENARIO C: Receive Ping (client receives + replies)" << std::endl;
	std::cout << "[*] Server 10.0.0.10 --> Client 10.0.0.15" << std::endl;
	std::cout << "[*] Client will automatically reply with ECHO_REPLY" << std::endl;
	std::cout << "===============================\n" << std::endl;

	/* SERVER sends the ping this time — CLIENT receives and auto-replies */
	ICMP_server.sendToL4((byte *)test, testlen, "10.0.0.15", "", ICMP::Flags::ECHO_REQUEST);

	std::string input;
	std::cout << "\nPress ENTER to quit: ";
	getline(std::cin, input);
}

/************************************************************************/
/*                            Main Menu                                 */
/************************************************************************/
void main(int argc, char *argv[]) {

	std::cout << "\n============================================" << std::endl;
	std::cout << "  NetlabTAU Lab 01 - ICMP Ping Test Suite" << std::endl;
	std::cout << "============================================" << std::endl;
	std::cout << "  A) External Ping  (10.0.0.15 -> 20.0.0.10, different subnet)" << std::endl;
	std::cout << "  B) Internal Ping  (10.0.0.15 -> 10.0.0.10, same subnet)" << std::endl;
	std::cout << "  C) Receive Ping   (10.0.0.10 -> 10.0.0.15, client receives)" << std::endl;
	std::cout << "============================================" << std::endl;
	std::cout << "  Select scenario (A/B/C): ";

	std::string choice;
	getline(std::cin, choice);

	if (choice == "A" || choice == "a") {
		testExternal();
	}
	else if (choice == "B" || choice == "b") {
		testInternal();
	}
	else if (choice == "C" || choice == "c") {
		testReceive();
	}
	else {
		std::cout << "Invalid choice. Exiting." << std::endl;
	}
}