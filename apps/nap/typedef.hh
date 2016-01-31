/*
 * typedef.hh
 *
 *  Created on: 17 Apr 2015
 *      Author: Sebastian Robitzsch <sebastian.robitzsch@interdigital.com>
 *
 * This file is part of Blackadder.
 *
 * Blackadder is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * Blackadder is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Blackadder.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef TYPEDEF_HH_
#define TYPEDEF_HH_

#include "def.hh"
#include "enumerations.hh"
#include <string>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/program_options.hpp>
#include <boost/date_time.hpp>
#include <functional>
#include <pcap.h>
#include <deque>
#include <boost/generator_iterator.hpp>
#include <boost/random/linear_congruential.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/uniform_real.hpp>
#include <boost/random/variate_generator.hpp>
using namespace std;
#define ID_LEN 16								/*!< Inherited from
Blackadder->PURSUIT_ID_LEN */
#define MAX_MESSAGE_PAYLOAD 65535				/*!< PCAP buffer for a single packet */
#define PACKET_TIMEOUT 3600000					/*!< Timeout in ms to delete
packet from internal NAP buffer */
typedef string ICN_ID;							/*!< Unique ICN identifier
(Scope)*/
typedef string NODE_ID;							/*!< Node ID of length ID_LEN */
typedef string URL;								/*!< URL */
typedef uint32_t IP_ADDRESS;					/*!< IP Address */
typedef uint32_t NETMASK;						/*!< Subnet mask for routing
prefix */
typedef string EUI48;							/*!< EUI-48 address (MAC) */
typedef string EUI64;							/*!< EUI-48 address (MAC) */
typedef char DEVICE;							/*!< the name of a networking
device in Linux, e.g., eth0 */
typedef struct pcap_pkthdr PACKET_HDR_STRUCT;	/*!< PCAP packet header struct */
typedef pcap_t PCAP_HANDLER;					/*!< PCAP packet handler pointer */
typedef const u_char PCAP_PACKET;				/*!< Used when calling PCAP to
store a single packet temporarily */
typedef uint8_t PACKET;
//typedef bpf_u_int32 PACKET_LENGTH;
typedef uint16_t PACKET_LENGTH;				/*!< The length of a packet to
be sent/buffered */
typedef uint16_t PORT;							/*!< Port number of transport
protocol */
typedef uint16_t ROOT_NAMESPACE;					/*!< Root namespace of the scope
tree. Look up RootNamespace enum */
typedef uint8_t MODE;			/*!< for enumeration Modes */
typedef struct PacketDescription
{
	PACKET *packet;
	PACKET_LENGTH packetLength;
	boost::posix_time::ptime timeStamp;
} PACKET_DESCRIPTION;
/*!
 * \brief Routing prefix description
 *
 * This struct describes a routing prefix using the IP address, the netmask, and
 * holds additional information such as the resulting mask when applying the
 * netmask to the given IP address and the hashed prefix
 */
struct ROUTING_PREFIX {
	IP_ADDRESS networkAddress;	/*!< Network address describing the prefix */
	NETMASK netmask;		/*!< The netmask for the prefix */
	uint32_t appliedMask;	/*!< Applied mask (ipAddress & netmask) */
	unsigned int hashedPrefix;	/*!< Hashed routing prefix */
};
typedef hash<string> HASH_STR;	/*!< Typedef for hashing IDs of type string */
/*** Typedefs for NAP / Proxy / * API *****************************************/
typedef char FQDN;
typedef uint8_t FQDN_LENGTH;
typedef uint16_t HTTP_METHOD;
typedef uint16_t URL_LENGTH;
typedef char RESOURCE;
typedef uint16_t RESOURCE_LENGTH;
typedef uint16_t PORT_IDENTIFIER;
/*** Typedefs for Transport Protocol ******************************************/
typedef uint8_t TRANSPORT_STATE;
typedef uint16_t TRANSPORT_SEQUENCE;
typedef uint16_t TRANSPORT_KEY;
struct TRANSPORT_HEADER
{
	TRANSPORT_STATE state;
	TRANSPORT_SEQUENCE sequence;
	TRANSPORT_KEY key;
	PACKET_LENGTH size = sizeof(TRANSPORT_STATE)
			+ sizeof(TRANSPORT_SEQUENCE)
			+ sizeof(TRANSPORT_KEY);
};
struct FRAGMENTED_PACKET_DESCRIPTION
{
	PACKET_DESCRIPTION packetDescription;
	TRANSPORT_STATE transportState;
};
typedef map <TRANSPORT_SEQUENCE, FRAGMENTED_PACKET_DESCRIPTION>
ASSEMBLY_PACKET_MAP;
typedef string ASSEMBLY_BUFFER_UNIQUE_KEY; /*!< This string is a concatenation
of ICN ID, TRANSPORT_PROTOCOL_KEY and NODE_ID */
typedef map <ASSEMBLY_BUFFER_UNIQUE_KEY, ASSEMBLY_PACKET_MAP>
ASSEMBLY_BUFFER_MAP;
/*** Typedefs for Proxy Packet Forwarding *************************************/
typedef std::deque<PACKET_DESCRIPTION> FORWARD_PACKET_DEQUE;
/*** Typedefs for HTTP Namespace **********************************************/
typedef uint16_t HTTP_METHOD;
typedef struct HttpHeader
{
	HTTP_METHOD method;
} HTTP_HEADER_DESCRIPTION;
typedef struct HttpPacket
{
	HTTP_HEADER_DESCRIPTION header;
	PACKET_DESCRIPTION payload;
} HTTP_PACKET;
struct ICN_ID_DESCRIPTION_HTTP {
	uint16_t httpMethod;
	string fqdn;
	int hashedFqdn;
	string resource;
	int hashedResource;
	IP_ADDRESS ipAddress;		/*!< IP of the web server obtained through FQDN
	registration when bootstrapping the NAP */
	bool forwardingPolicy;		/*!< Forwarding policy */
	bool scopesPublished;		/*!< Set to true means this ICN	ID has been
	published to the RV*/
	PORT_IDENTIFIER portIdentifier;	/*!< PID of the sender */
};
typedef map<ICN_ID, ICN_ID_DESCRIPTION_HTTP> ICN_ID_DESCRIPTION_HTTP_MAP;
struct HTTP_PACKET_BUFFER_STRUCT {
	string resource;
	boost::posix_time::ptime timeStamp;	/*!< Corresponding time-stamp of when
		this HTTP packet has been received */
};
typedef deque< pair<ICN_ID, HTTP_PACKET_BUFFER_STRUCT> > PACKET_BUFFER_HTTP_DEQUE;
/*!< Buffer to temporarily store packets ready to be published */
/*** Co-incidental Multicast ***************************************************/
typedef map <URL, list<NODE_ID>> COINCIDENTAL_MULTICAST_MAP;
/*** Typedefs for IP Namespace ************************************************/
/*!
 * \brief ICN ID description
 *
 * This struct holds all information which was required to build the ICN ID
 * including boolean values describing certain states
 */
struct ICN_ID_DESCR_STRUCT {
	ROUTING_PREFIX routingPrefix;	/*!< Routing prefix (IP + netmask) */
	IP_ADDRESS ipAddress;			/*!< IP address represented by this ICN ID*/
	PORT port;						/*!< Port number of the destination IP
	endpoint */
	bool fwPolicy;					/*!< Forwarding policy */
	bool localInterface;			/*!< Set to true if this IP	address is the
	local interface */
	ICN_ID_DESCRIPTION_HTTP httpDescription;
	bool scopesPublished;			/*!< Set to true means this ICN	ID has been
	published to the RV */
};
typedef map<ICN_ID, ICN_ID_DESCR_STRUCT> ICN_ID_DESCRIPTION_IP_MAP;	/*!< map for
storing ICN ID and its corresponding IP+Port+forwarding policy */
typedef vector <IP_ADDRESS> IP_ADDRESS_VECTOR;		/*!< list of IP Addresses */
typedef vector <IP_ADDRESS>::iterator IP_ADDRESS_VECTOR_IT;	/*!< Iterator to I
P_ADDRESS_VECTOR*/
typedef vector <ROUTING_PREFIX> ROUTING_PREFIX_VECTOR;
typedef map <PORT, bool> EXTERNAL_PORTS_MAP;
/*!
 * \brief Packet buffer
 *
 * This struct allows to store a packet in the DB described by the actual packet
 * pointer, the packet length and a time stampt when this packet was added to
 * the struct
 */
struct PACKET_BUFFER_STRUCT {
	TRANSPORT_KEY key;
	PACKET_DESCRIPTION packetDescription;
};
typedef deque< pair<ICN_ID, PACKET_BUFFER_STRUCT> > PACKET_BUFFER_ICN_DEQUE; /*!<
Buffer to temporarily store packets ready to be published */
typedef deque< pair<IP_ADDRESS, PACKET_BUFFER_STRUCT> > PACKET_BUFFER_IP_DEQUE;
/*!< Buffer to temporarily store IP packets ready to be sent to one of the IP
endpoints */
typedef map<IP_ADDRESS, EUI48> IP_EUI48_MAP;		/*!< Map for ARP handler to
store allocated random MAC address */
typedef boost::minstd_rand BASE_GENERATOR_TYPE;		/*!< Generator for
generating uniform numbers */
#endif /* TYPEDEF_HH_ */
