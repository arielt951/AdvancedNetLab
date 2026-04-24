#include <WinSock2.h>
#include <iostream>
#include <cstdlib>

#include "NetlabTAU/include/L5/L5.h"
#include "NetlabTAU/include/L4/L4.h"
#include "NetlabTAU/include/L3/L3_impl.h"
#include "NetlabTAU/include/L2/L2.h"
#include "NetlabTAU/include/L1/NIC.h"

#include "NetlabTAU/include/L2/L2_ARP.h"

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
	/*  MAC addresses used by each role                                    */
	/*  These must match between client and server ARP entries!            */
	/* ================================================================== */
	const char* CLIENT_MAC = "aa:bb:cc:dd:ee:01";
	const char* SERVER_MAC = "aa:bb:cc:dd:ee:02";

	/* ================================================================== */
	/*  Role Selection Menu                                                */
	/* ================================================================== */
	std::cout << "============================================" << std::endl;
	std::cout << "  NetlabTAU Lab 01 - ICMP Ping/Pong" << std::endl;
	std::cout << "  (Using real network adapter)" << std::endl;
	std::cout << "============================================" << std::endl;
	std::cout << std::endl;
	std::cout << "  --- Scenario A: External Ping (different subnets) ---" << std::endl;
	std::cout << "  1) Client: 10.0.0.15  -->  ping 20.0.0.10 (via gateway)" << std::endl;
	std::cout << "  2) Server: 20.0.0.10  (wait for ping, auto-reply)" << std::endl;
	std::cout << std::endl;
	std::cout << "  --- Scenario B: Internal Ping (same subnet) ---" << std::endl;
	std::cout << "  3) Client: 10.0.0.15  -->  ping 10.0.0.10 (direct)" << std::endl;
	std::cout << "  4) Server: 10.0.0.10  (wait for ping, auto-reply)" << std::endl;
	std::cout << std::endl;
	std::cout << "  --- Scenario C: Receive Ping ---" << std::endl;
	std::cout << "  5) 10.0.0.10  -->  ping 10.0.0.15 (server pings client)" << std::endl;
	std::cout << "  6) 10.0.0.15  (wait, receive ping, auto-reply)" << std::endl;
	std::cout << std::endl;
	std::cout << "============================================" << std::endl;
	std::cout << "  Select role (1-6): ";

	std::string choice;
	getline(std::cin, choice);
	int role = atoi(choice.c_str());

	if (role < 1 || role > 6) {
		std::cout << "Invalid choice. Exiting." << std::endl;
		return;
	}

	/* ================================================================== */
	/*  Configure based on selected role                                   */
	/* ================================================================== */
	const char* my_ip		= nullptr;
	const char* my_mac		= nullptr;
	const char* my_gateway	= nullptr;
	const char* my_netmask	= "255.255.255.0";
	const char* peer_ip		= nullptr;
	const char* peer_mac	= nullptr;
	const char* arp_target_ip = nullptr;  /* IP whose MAC we need in ARP table */
	bool		is_sender	= false;
	const char* scenario_name = nullptr;

	switch (role) {
	case 1: /* Scenario A: Client (External) */
		my_ip = "10.0.0.15";  my_mac = CLIENT_MAC;  my_gateway = "10.0.0.1";
		peer_ip = "20.0.0.10"; peer_mac = SERVER_MAC;
		arp_target_ip = "10.0.0.1";  /* ARP: gateway -> server's MAC */
		is_sender = true;
		scenario_name = "A: External Ping (Client 10.0.0.15 -> Server 20.0.0.10 via gateway)";
		break;
	case 2: /* Scenario A: Server (External) */
		my_ip = "20.0.0.10";  my_mac = SERVER_MAC;  my_gateway = "20.0.0.1";
		peer_ip = "10.0.0.15"; peer_mac = CLIENT_MAC;
		arp_target_ip = "20.0.0.1";  /* ARP: gateway -> client's MAC */
		is_sender = false;
		scenario_name = "A: External Ping (Server 20.0.0.10, waiting for ping)";
		break;
	case 3: /* Scenario B: Client (Internal) */
		my_ip = "10.0.0.15";  my_mac = CLIENT_MAC;  my_gateway = nullptr;
		peer_ip = "10.0.0.10"; peer_mac = SERVER_MAC;
		arp_target_ip = "10.0.0.10"; /* ARP: server's IP -> server's MAC */
		is_sender = true;
		scenario_name = "B: Internal Ping (Client 10.0.0.15 -> Server 10.0.0.10, same subnet)";
		break;
	case 4: /* Scenario B: Server (Internal) */
		my_ip = "10.0.0.10";  my_mac = SERVER_MAC;  my_gateway = nullptr;
		peer_ip = "10.0.0.15"; peer_mac = CLIENT_MAC;
		arp_target_ip = "10.0.0.15"; /* ARP: client's IP -> client's MAC */
		is_sender = false;
		scenario_name = "B: Internal Ping (Server 10.0.0.10, waiting for ping)";
		break;
	case 5: /* Scenario C: Server sends ping to client */
		my_ip = "10.0.0.10";  my_mac = SERVER_MAC;  my_gateway = nullptr;
		peer_ip = "10.0.0.15"; peer_mac = CLIENT_MAC;
		arp_target_ip = "10.0.0.15";
		is_sender = true;
		scenario_name = "C: Receive Ping (10.0.0.10 pings 10.0.0.15, expects auto-reply)";
		break;
	case 6: /* Scenario C: Client waits for ping */
		my_ip = "10.0.0.15";  my_mac = CLIENT_MAC;  my_gateway = nullptr;
		peer_ip = "10.0.0.10"; peer_mac = SERVER_MAC;
		arp_target_ip = "10.0.0.10";
		is_sender = false;
		scenario_name = "C: Receive Ping (10.0.0.15 waiting, will auto-reply)";
		break;
	}

	/* ================================================================== */
	/*  Create the network stack                                           */
	/* ================================================================== */
	std::cout << "\n===============================" << std::endl;
	std::cout << "[*] " << scenario_name << std::endl;
	std::cout << "[*] My IP: " << my_ip << "  MAC: " << my_mac << std::endl;
	std::cout << "[*] Peer IP: " << peer_ip << "  MAC: " << peer_mac << std::endl;
	std::cout << "===============================\n" << std::endl;

	inet_os inet = inet_os();

	/* NIC — the framework will present a list of adapters to choose from */
	NIC nic(inet, my_ip, std::string(my_mac), my_gateway, my_netmask, true, "");

	/* L2 — Ethernet datalink layer */
	L2_impl datalink(inet);
	inet.datalink(&datalink);

	/* ARP */
	inet.arp(new L2_ARP_impl(inet));

	/* L3 — IP layer */
	inet.inetsw(new L3_impl(inet, 0, 0, 0), protosw::SWPROTO_IP);
	inet.inetsw(new L3_impl(inet, SOCK_RAW, IPPROTO_RAW, protosw::PR_ATOMIC | protosw::PR_ADDR), protosw::SWPROTO_IP_RAW);
	inet.domaininit();

	/* L4 — ICMP layer */
	L4 icmp(true, inet);
	inet.setICMP(&icmp);

	/* Static ARP entry: map the next-hop IP to the peer's MAC */
	inet.arp()->insertPermanent(inet_addr(arp_target_ip), std::string(peer_mac));

	/* Connect — opens pcap on the selected adapter and starts sniffer thread */
	std::cout << "[*] Connecting to network adapter..." << std::endl;
	inet.connect(0U);
	std::cout << "[*] Connected! Sniffer thread is active.\n" << std::endl;

	/* ================================================================== */
	/*  Execute the scenario                                               */
	/* ================================================================== */
	if (is_sender) {
		std::cout << "[*] Sending ICMP ECHO_REQUEST to " << peer_ip << "..." << std::endl;
		icmp.sendToL4((byte *)test, testlen, peer_ip, "", ICMP::Flags::ECHO_REQUEST);

		/* Wait for the reply to arrive (sniffer is running in background) */
		Sleep(2000);
		std::cout << "\n[*] Scenario complete. ECHO_REQUEST sent and ECHO_REPLY received." << std::endl;
	}
	else {
		std::cout << "[*] Waiting for incoming ICMP ECHO_REQUEST..." << std::endl;
		std::cout << "[*] (The sniffer thread will automatically capture and process incoming frames)" << std::endl;
		std::cout << "[*] (ECHO_REPLY will be sent automatically when a request arrives)" << std::endl;
		std::cout << "\n[*] Press ENTER when you are done to exit..." << std::endl;
	}

	/* Wait for user before exiting */
	std::string input;
	getline(std::cin, input);
	std::cout << "Exiting..." << std::endl;

	/* Use exit(0) to skip destructors — avoids crash from sniffer threads */
	exit(0);
}