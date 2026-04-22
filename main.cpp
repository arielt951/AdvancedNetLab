#include <WinSock2.h>
#include <iostream>
#include <cstdlib>

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
/*                            Main                                      */
/************************************************************************/
void main(int argc, char *argv[]) {

	const char* test = "NetlabPingPongTest";
	size_t testlen = string(test).length();

	/* ================================================================== */
	/*  Topology A: External (different subnets, gateway routing)         */
	/*  Client 10.0.0.15/24 (gw 10.0.0.1) <-> Server 20.0.0.10/24       */
	/* ================================================================== */
	inet_os ext_cli_os = inet_os();
	NIC ext_cli_nic(ext_cli_os, "10.0.0.15", "b1:b1:b1:b1:b1:b1", "10.0.0.1", "255.255.255.0", true, "");

	L2_impl ext_cli_dl(ext_cli_os);
	ext_cli_os.datalink(&ext_cli_dl);
	ext_cli_os.arp(new L2_ARP_impl(ext_cli_os));
	ext_cli_os.inetsw(new L3_impl(ext_cli_os, 0, 0, 0), protosw::SWPROTO_IP);
	ext_cli_os.inetsw(new L3_impl(ext_cli_os, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	ext_cli_os.domaininit();
	L4 ext_cli_icmp(true, ext_cli_os);
	ext_cli_os.setICMP(&ext_cli_icmp);

	inet_os ext_srv_os = inet_os();
	NIC ext_srv_nic(ext_srv_os, "20.0.0.10", "a1:a1:a1:a1:a1:a1", "20.0.0.1", "255.255.255.0", true, "");

	L2_impl ext_srv_dl(ext_srv_os);
	ext_srv_os.datalink(&ext_srv_dl);
	ext_srv_os.arp(new L2_ARP_impl(ext_srv_os));
	ext_srv_os.inetsw(new L3_impl(ext_srv_os, 0, 0, 0), protosw::SWPROTO_IP);
	ext_srv_os.inetsw(new L3_impl(ext_srv_os, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	ext_srv_os.domaininit();
	L4 ext_srv_icmp(true, ext_srv_os);
	ext_srv_os.setICMP(&ext_srv_icmp);

	/* ARP: client's gateway -> server's MAC, server's gateway -> client's MAC */
	ext_cli_os.arp()->insertPermanent(inet_addr("10.0.0.1"), "a1:a1:a1:a1:a1:a1");
	ext_srv_os.arp()->insertPermanent(inet_addr("20.0.0.1"), "b1:b1:b1:b1:b1:b1");

	L2_impl_set_peers(&ext_cli_dl, &ext_srv_dl);
	ext_cli_os.connect(0U);
	ext_srv_os.connect(0U);

	/* ================================================================== */
	/*  Topology B/C: Internal (same subnet, direct routing)              */
	/*  Client 10.0.0.25/24 <-> Server 10.0.0.20/24                      */
	/* ================================================================== */
	inet_os int_cli_os = inet_os();
	NIC int_cli_nic(int_cli_os, "10.0.0.25", "b2:b2:b2:b2:b2:b2", nullptr, "255.255.255.0", true, "");

	L2_impl int_cli_dl(int_cli_os);
	int_cli_os.datalink(&int_cli_dl);
	int_cli_os.arp(new L2_ARP_impl(int_cli_os));
	int_cli_os.inetsw(new L3_impl(int_cli_os, 0, 0, 0), protosw::SWPROTO_IP);
	int_cli_os.inetsw(new L3_impl(int_cli_os, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	int_cli_os.domaininit();
	L4 int_cli_icmp(true, int_cli_os);
	int_cli_os.setICMP(&int_cli_icmp);

	inet_os int_srv_os = inet_os();
	NIC int_srv_nic(int_srv_os, "10.0.0.20", "a2:a2:a2:a2:a2:a2", nullptr, "255.255.255.0", true, "");

	L2_impl int_srv_dl(int_srv_os);
	int_srv_os.datalink(&int_srv_dl);
	int_srv_os.arp(new L2_ARP_impl(int_srv_os));
	int_srv_os.inetsw(new L3_impl(int_srv_os, 0, 0, 0), protosw::SWPROTO_IP);
	int_srv_os.inetsw(new L3_impl(int_srv_os, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	int_srv_os.domaininit();
	L4 int_srv_icmp(true, int_srv_os);
	int_srv_os.setICMP(&int_srv_icmp);

	/* ARP: direct resolution (same subnet) */
	int_cli_os.arp()->insertPermanent(inet_addr("10.0.0.20"), "a2:a2:a2:a2:a2:a2");
	int_srv_os.arp()->insertPermanent(inet_addr("10.0.0.25"), "b2:b2:b2:b2:b2:b2");

	L2_impl_set_peers(&int_cli_dl, &int_srv_dl);
	int_cli_os.connect(0U);
	int_srv_os.connect(0U);

	/* ================================================================== */
	/*  Interactive Loop                                                   */
	/* ================================================================== */
	std::string choice, input;

	while (true) {
		std::cout << "\n============================================" << std::endl;
		std::cout << "  NetlabTAU Lab 01 - ICMP Ping Test Suite" << std::endl;
		std::cout << "============================================" << std::endl;
		std::cout << "  A) External Ping  (10.0.0.15 -> 20.0.0.10, different subnet)" << std::endl;
		std::cout << "  B) Internal Ping  (10.0.0.25 -> 10.0.0.20, same subnet)" << std::endl;
		std::cout << "  C) Receive Ping   (10.0.0.20 -> 10.0.0.25, client receives)" << std::endl;
		std::cout << "  Q) Quit" << std::endl;
		std::cout << "============================================" << std::endl;
		std::cout << "  Select scenario (A/B/C/Q): ";

		getline(std::cin, choice);

		if (choice == "A" || choice == "a") {
			std::cout << "\n===============================" << std::endl;
			std::cout << "[*] SCENARIO A: External Ping" << std::endl;
			std::cout << "[*] Client 10.0.0.15 --> Server 20.0.0.10 (via gateway 10.0.0.1)" << std::endl;
			std::cout << "===============================\n" << std::endl;
			ext_cli_icmp.sendToL4((byte *)test, testlen, "20.0.0.10", "", ICMP::Flags::ECHO_REQUEST);
		}
		else if (choice == "B" || choice == "b") {
			std::cout << "\n===============================" << std::endl;
			std::cout << "[*] SCENARIO B: Internal Ping (same subnet)" << std::endl;
			std::cout << "[*] Client 10.0.0.25 --> Server 10.0.0.20 (direct)" << std::endl;
			std::cout << "===============================\n" << std::endl;
			int_cli_icmp.sendToL4((byte *)test, testlen, "10.0.0.20", "", ICMP::Flags::ECHO_REQUEST);
		}
		else if (choice == "C" || choice == "c") {
			std::cout << "\n===============================" << std::endl;
			std::cout << "[*] SCENARIO C: Receive Ping (client receives + replies)" << std::endl;
			std::cout << "[*] Server 10.0.0.20 --> Client 10.0.0.25" << std::endl;
			std::cout << "[*] Client will automatically reply with ECHO_REPLY" << std::endl;
			std::cout << "===============================\n" << std::endl;
			int_srv_icmp.sendToL4((byte *)test, testlen, "10.0.0.25", "", ICMP::Flags::ECHO_REQUEST);
		}
		else if (choice == "Q" || choice == "q") {
			std::cout << "Exiting..." << std::endl;
			break;
		}
		else {
			std::cout << "Invalid choice. Try again." << std::endl;
			continue;
		}

		Sleep(500);  /* Let async prints flush */
		std::cout << "\nPress ENTER to return to menu...";
		getline(std::cin, input);
	}

	/* Use exit(0) to skip destructors — avoids crash from sniffer threads
	 * referencing objects during stack unwinding. */
	exit(0);
}