#pragma once

#include "../L3/L3.h"
#include "../infra/HWAddress.hpp"

/********************************************************************************************/
/*										INTERFACE											*/
/********************************************************************************************/

struct rtentry;

// Represents a Layer 2 interface (Ethernet).
class L2 {
public:

	struct ether_header;

	// Constructor
	L2(class inet_os &inet);

	// Destructor
	virtual ~L2();

	/* ether_output - A function used to pass the data from L2 to L1.
	*		m - The std::shared_ptr<std::vector<byte>> to strip.
	*		it - The iterator, as the current offset in the vector.
	*		dst - the destination address of the packet.
	*		rt - routing information.
	*/
	virtual void ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt) = 0;

	/* ether_input - A function used to pass the data from L1 to L2.
	* 	   m - The std::shared_ptr<std::vector<byte>> to strip.
	* 	   it - The iterator, as the current offset in the vector.
	* 	   eh - the Ethernet header of the packet.
	*/
	virtual void ether_input(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct ether_header *eh) = 0;

protected:
	class inet_os &inet; /*!< The inet_os owning this protocol. */
};

/********************************************************************************************/
/*										SOLUTION											*/
/********************************************************************************************/


/************************************************************************/
/*							ethernet_header                             */
/************************************************************************/

struct L2::ether_header 
{
public:


	// HWAddress is a class that represents a MAC address.
	typedef netlab::HWAddress<>		mac_addr;

	mac_addr ether_dhost;   /* The Ethernet destination host */
	mac_addr ether_shost;   /* The Ethernet source host */
	u_short	ether_type;		/* Type of the Ethernet (ETHERTYPE_) */
	
	// Ethernet types
	enum ETHERTYPE_ 
	{
		ETHERTYPE_PUP = 0x0200,		/*!< PUP protocol */
		ETHERTYPE_IP = 0x0800,		/*!< IP protocol */
		ETHERTYPE_ARP = 0x0806,		/*!< Address resolution protocol */
		ETHERTYPE_REVARP = 0x8035,	/*!< reverse Address resolution protocol */
		ETHERTYPE_TRAIL = 0x1000,	/*!< Trailer packet */
		ETHERTYPE_NTRAILER = 16		/*!< The ETHERTYPE ntrailer option */
	};

	// Ethernet header lengths
	enum ETH_
	{
		ETH_ALEN = 6,			/*!< Octets in one Ethernet addr	 */
		ETH_HLEN = 14,			/*!< Total octets in header.	 */
		ETH_ZLEN = 60,			/*!< Min. octets in frame sans FCS */
		ETH_DATA_LEN = 1500,	/*!< Max. octets in payload	 */
		ETH_FRAME_LEN = 1514,	/*!< Max. octets in frame sans FCS */
		ETH_FCS_LEN = 4			/*!< Octets in the FCS		 */
	};

	// Ethernet addresses lengths
	enum ETHER_
	{
		ETHER_ADDR_LEN = ETH_ALEN,							/*!< size of Ethernet addr */
		ETHER_TYPE_LEN = 2,									/*!< bytes in type field */
		ETHER_CRC_LEN = 4,									/*!< bytes in CRC field */
		ETHER_HDR_LEN = ETH_HLEN,							/*!< total octets in header */
		ETHER_MIN_LEN = (ETH_ZLEN + ETHER_CRC_LEN),			/*!< min packet length */
		ETHER_MAX_LEN = (ETH_FRAME_LEN + ETHER_CRC_LEN)		/*!< max packet length */
	};

	/*
		Constructor
			shost - The Ethernet source host
			dhost - The Ethernet destination host
			type - Type of the Ethernet \see ETHERTYPE_
	*/
	ether_header(const mac_addr shost, const mac_addr dhost, const ETHERTYPE_ type = ETHERTYPE_IP);
	
	/*
		Constructor
			type - Type of the Ethernet \see ETHERTYPE_
	*/
	ether_header(const ETHERTYPE_ type = ETHERTYPE_IP);
};

/************************************************************************/
/*							L2_impl class								*/
/************************************************************************/

class L2_impl : public L2
{
public:

	// HWAddress is a class that represents a MAC address.
	typedef netlab::HWAddress<>		mac_addr;

	// Global static default parameters
	enum L2_DEFAULT
	{
		ETHERMTU = L2::ether_header::ETH_DATA_LEN,  /*!< The Ethernet MTU */
		ETHERMIN = (L2::ether_header::ETHER_MIN_LEN - L2::ether_header::ETHER_HDR_LEN - L2::ether_header::ETHER_CRC_LEN),   /*!< The Ethernet minimum size */
		EHOSTDOWN = 64		/*!<  The Ethernet Host is down */
	};

	// Flags from the legacy mbuf struct, used for marking packet as M_MCAST or M_BCAST
	enum M_
	{
		M_EXT = 0x0001,		/*!< has associated external storage */
		M_PKTHDR = 0x0002,	/*!< start of record */
		M_EOR = 0x0004,		/*!< end of record */
		M_BCAST = 0x0100,	/*!< send/received as link-level broadcast */
		M_MCAST = 0x0200	/*!< send/received as link-level multicast */
	};

	// Constructor
	L2_impl(class inet_os &inet);

	/*
		ether_output - A function used to pass the data from L2 to L1.
			m - The std::shared_ptr<std::vector<byte>> to strip.
			it - The iterator, as the current offset in the vector.
			dst - the destination address of the packet.
			rt - routing information.
	*/
	virtual void ether_output(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct sockaddr *dst, struct L3::rtentry *rt);

	/*
		ether_input - A function used to pass the data from L1 to L2.
			m - The std::shared_ptr<std::vector<byte>> to strip.
			it - The iterator, as the current offset in the vector.
			eh - the Ethernet header of the packet.
	*/
	virtual void ether_input(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct ether_header *eh);
};