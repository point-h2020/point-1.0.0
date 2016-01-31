/*
 * database.hh
 *
 *  Created on: 18 May 2015
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
#ifndef DATABASE_HH_
#define DATABASE_HH_
#include "typedef.hh"
#include <log4cxx/logger.h>
#include <boost/thread/mutex.hpp>
/*!
 * \brief Database of the NAP
 *
 * This class is the API to the NAPs data-base which stores all values in
 * private variables which are accessible (r/w) via public functions. The
 * class also implements a mutex functionality to allow transaction safe
 * access to the DB across the NAP.
 */
class Database {
public:
	bool runNap;/*!< Set to FALSE when NAP is terminated by user*/
	ROUTING_PREFIX hostRoutingPrefix;
	IP_ADDRESS hostNetworkAddress;
	IP_ADDRESS hostIpAddressDevice;
	NETMASK hostNetmask;
	TRANSPORT_SEQUENCE sequenceNumber;
	pair<IP_ADDRESS, EUI48> ipGateway;	/*!< IP and MAC of the IP gateway */
	bool icnGateway;
	boost::mutex mutexSequenceNumbers;	/*!< DB mutex to lock/unlock
	incrementing sequence number  */
	uint8_t threadPriority = 0;
#ifdef DEBUG
	Database(log4cxx::LoggerPtr logger)
	: _logger(logger)
#else
	Database()
#endif
	{
		runNap = true;
		/* In host-based deployments (network address is a /32 net the routing
		 * prefix for this host is still different. That is why hostNetworkAddress
		 * as well as the hostRoutingPrefix is used */
		hostRoutingPrefix.networkAddress = 0xffffffff;
		hostRoutingPrefix.netmask = 0xffffffff;
		hostNetworkAddress = 0xffffffff;
		hostIpAddressDevice = 0xffffffff;
		hostNetmask = 0xffffffff;
		sequenceNumber = 0;
		ipGateway.first = 0x0;
		ipGateway.second = "";
		icnGateway = false;
	}
	~Database();
	void addIcnId(ICN_ID icnId);
	/*!
	 * \brief Add an ICN ID to the data-base
	 *
	 * This function ass an ICN ID from the IP namespace to the database. Note,
	 * as the database is always used as a reference across all functions, the
	 * locking of the database in order to add a new ICN ID is done
	 * automatically using boost::mutex.
	 *
	 * \param icnId The ICN ID which should be added
	 * \param ipAddress The IP address which should be added
	 * \param port The port number which should be added
	 * \param localInterface Boolean indicating if this IP is the local NAP's
	 * interface
	 */
	void addIcnId(ICN_ID icnId, IP_ADDRESS ipAddress, PORT port,
			bool localInterface);
	/*!
	 * \brief
	 *
	 * tba
	 *
	 * \param icnId
	 * \param type TYPE_FQDN || TYPE_URL
	 */
	void addIcnId(ICN_ID icnId, uint8_t type);
	/*!
	 * \brief
	 *
	 * tba
	 *
	 * \param icnId
	 * \param fqdn
	 * \param ipAddress
	 */
	void addIcnId(ICN_ID icnId, string fqdn, IP_ADDRESS ipAddress);
	/*!
	 * \brief Adding an ICN ID of namespace HTTP to the database (HTTP Request)
	 *
	 * This function allows to add an ICN ID to the database which represents
	 * the scope tree of an HTTP-based abstraction for HTTP Requests
	 *
	 * \param icnId The ICN ID
	 * \param fqdn This string holds the FQDN
	 * \param url This string holds the URL
	 */
	void addIcnId(ICN_ID icnId, string fqdn, string resource);
	/*!
	 * \brief
	 *
	 * \param icnId
	 */
	void addIcnId(ICN_ID icnId, string fqdn, string resource,
			PORT_IDENTIFIER portIdentifier);
	/*!
	 * \brief Adding IP <> EUI48 pair to DB
	 *
	 * This function adds an IP address and its corresponding MAC address to
	 * the database.
	 *
	 * \param ipAddress The IP address which should be added
	 * \param eui48 The MAC address which belongs to the give IP
	 */
	void addIpEui48Pair(IP_ADDRESS ipAddress, EUI48 eui48);
	/*!
	 * \brief Add an IP endpoint to the DB
	 *
	 * This function adds an IP address to the napIpEndpoints vector which holds
	 * all IP endpoints of the NAP
	 *
	 * \param ipAddress The IP address which should be added to the DB
	 */
	void addIpEndpoint(IP_ADDRESS ipAddress);
	/*!
	 * \brief Add a packet to the ICN buffer
	 *
	 * This function adds an ICN packet ready to be published to the buffer
	 * using the provided ICN ID as the map key. Note, as this function uses
	 * std::deque there's no need to lock() and unclock() the NAP database.
	 *
	 * \param icnId The ICN ID for which a packet must be buffered
	 * \param packet Pointer to the actual packet
	 * \param packetLength The length of the packet the pointer of parameter 2,
	 * packet, points to
	 * \param timeStamp The timestamp of when the packet has been captured
	 */
	void addPacketToIcnBuffer(ICN_ID icnId,	PCAP_PACKET *packet,
			PACKET_LENGTH packetLength,	boost::posix_time::ptime timeStamp);
	/*!
	 * \brief Add a packet to the ICN buffer
	 *
	 * TODO
	 *
	 * \param icnId
	 * \param key
	 */
	void addPacketToIcnBuffer(ICN_ID icnId, TRANSPORT_KEY key,
				PCAP_PACKET *packet, PACKET_LENGTH packetLength,
				boost::posix_time::ptime timeStamp);
	/*!
	 * \brief Add an HTTP packet to ICN buffer
	 *
	 * This function adds an HTTP packet ready to be published to the ICN buffer
	 * using the provided ICN ID as the unique identifier.
	 *
	 * \param icnId The ICN ID under which the resource should be published
	 * \param httpMethod
	 * \param fqdn
	 * \param resource The URL's resource
	 * \param timeStamp The time when the HTTP packet was initially received
	 *
	void addPacketToIcnBuffer(ICN_ID icnId, uint16_t httpMethod,
			string fqdn, string resource, boost::posix_time::ptime timeStamp);*/
	/*!
	 * \brief Add an IP packet to the buffer using its unique ICN ID
	 *
	 * This function adds an IP packet ready to be published to the buffer
	 * using the provided IP address as the map key.
	 *
	 * \param ipAddress The IP address for which a packet must be buffered
	 * \param packet Pointer to the actual packet
	 * \param packetLength The length of the packet the pointer of parameter 2,
	 * packet, points to
	 */
	void addPacketToIpBuffer(IP_ADDRESS ipAddress, PCAP_PACKET *packet,
				PACKET_LENGTH packetLength);
	/*!
	 *
	 */
	void addPacketToAssemblyBuffer(TRANSPORT_HEADER header,
			ICN_ID icnId, PACKET *transportProtocolPayload,
			PACKET_LENGTH transportProtocolPayloadLength);
	/*!
	 *
	 */
	void addPacketToAssemblyBuffer(TRANSPORT_HEADER header,
			ICN_ID icnId, string nodeId, PACKET *transportProtocolPayload,
			PACKET_LENGTH transportProtocolPayloadLength);
	/*!
	 * \brief Add a routing prefix to the DB
	 *
	 * This function adds a routing prefix to the list of known routing prefixes
	 * in the DB. Note that there is no check conducted whether or not the given
	 * routing prefix does already exist in the vector.
	 *
	 * \param routingPrefix The routing prefix which shall be added to the DB
	 */
	void addRoutingPrefix(ROUTING_PREFIX routingPrefix);
	/*!
	 * \brief
	 */
	void assemblyBufferCleaner();
	/*!
	 * \brief Check if any packet is queued for a particular ICN ID
	 *
	 * This function checks the buffer if any packet is queued for a given ICN
	 * ID. Note, as the utlised standard lirbary std::deque is transaction safe
	 * by default, this function does not slow down the NAP by any means.
	 *
	 * \param icnId The ICN ID which should be looked up in the buffer
	 * \return This function returns a boolean indicating whether a packet is
	 * available in the packet for the given ICN ID (true) or not (false)
	 */
	bool checkForPacketInIcnBuffer(ICN_ID icnId);
	/*!
	 * \brief Check if IP packet buffer has a packet for given IP address
	 *
	 * The function checks if at least on IP packet is available to be sent to a
	 * particular IP endpoint
	 *
	 * \param ipAddress The IP address of the endpoint for which the IP buffer
	 * should be checked
	 *
	 * \return Boolean indicating whether at least one packet is available in
	 * the buffer (true) or not (false)
	 */
	bool checkForPacketInIpBuffer(IP_ADDRESS ipAddress);
	/*!
	 * \brief Check forwarding policy for ICN ID
	 *
	 * This function checks if packets towards from a given ICN ID are allowed
	 * to be published into the ICN or towards the IP network.
	 *
	 * \param icnId The ICN ID which should be checked
	 * \return A boolean is returned stating of the packet can be forwarded
	 * (TRUE) or not (FALSE)
	 */
	bool checkFwPolicy(ICN_ID icnId);
	/*!
	 * \brief
	 */
	void coincidentalMulticastAddNode(URL url, NODE_ID nodeId);
	/*!
	 * \brief
	 */
	bool coincidentalMulticastGetAllNodeIds(URL url,
			list<NODE_ID> &listOfNodeIds);
	/*!
	 * \brief Delete the ICN ID and its descriptor struct
	 *
	 * The given ICN ID is looked up in the DB and if found is deleted including
	 * all values.
	 *
	 * \param icnId The ICN ID which should be removed from DB
	 */
	void deleteIcnId(ICN_ID icnId);
	/*!
	 * \brief
	 *
	 * \param mapKey
	 */
	void deletePacketFromAssemblyBuffer(string mapKey);
	/*!
	 * \brief Find an ICN ID in the database
	 *
	 * This function looks up a given ICN ID in the database. Note, this
	 * function uses boost::mutex in order to allow transaction safe operations.
	 * Based on the root scope this function determines in which map it searches
	 * for the given ICN ID.
	 *
	 * \param icnId The ICN ID which should be looked up
	 *
	 * \return Boolean indicating whether given ICN ID was found (true) or not
	 * (false)
	 */
	bool findIcnId(ICN_ID icnId);
	/*!
	 * \brief
	 */
	bool findTimedOutPacketinAssemblyBuffer(string &mapKey);
	/*!
	 * \brief Generate random MAC address
	 *
	 * This function generates a random MAC address (EUI48) using the
	 * unassigned address space 00-03-00 - 00-51-FF according to
	 * https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xml
	 *
	 * \return The generates MAC address in format EUI48
	 */
	EUI48 generateEui48Address();
	/*!
	 * \brief Obtaining the MAC address for a given IP
	 *
	 * This function looks up the list of known IP addresses in arpTable and
	 * returns the MAC address as an EUI48.
	 *
	 * \param ipAddress The IP address for which the MAC address is sought
	 * \param eui48 Reference into which this function writes the MAC
	 *
	 * \return Boolean indicating whether MAC has been written into eui48 (true)
	 * or not (false)
	 */
	bool getEui48ForIp(IP_ADDRESS ipAddress, EUI48 &eui48);
	/*!
	 * \brief Obtain an ICN ID from the DB
	 *
	 * This function checks the DB for stored ICN IDs. If one has been found, it
	 * is returned.
	 *
	 * \param icnId Reference to a variable which will hold the ICN ID
	 *
	 * \return Boolean indicating whether or not an ICN ID has been found in DB
	 */
	bool getFirstIcnIdFromDatabase(ICN_ID &icnId);
	/*!
	 * \brief Retrieving the ICN ID from the DB for a given IP address and port
	 *
	 * This function checks the DB if an ICN ID has been saved for the given IP
	 * address and corresponding port number.
	 *
	 * \param ipAddress The IP address which should be used to look up an ICN
	 * ID
	 * \param port The port number which should be used to look up an ICN ID
	 * \param icnId Reference into which the ICN ID is written
	 *
	 * \return Returns the ICN ID under which the data must be published
	 */
	bool getIcnId(IP_ADDRESS ipAddress, PORT port, ICN_ID &icnId);
	/*!
	 * \brief
	 */
	bool getIcnIdUrl(ICN_ID icnId, ICN_ID &icnIdUrl);
	/*!
	 * \brief Obtain the IP address from an ICN ID
	 *
	 * This function allows to obtain the IP address of the endpoint for which
	 * the ICN ID was generated assuming that the ICN ID is following the IP
	 * namespace abstraction. In case the function is called with an ICN ID that
	 * is not using the IP namespace abstraction, it automatically returns false
	 *
	 * \param icnId The ICN ID for which the IP should be obtained
	 * \param ipAddress Reference to the IP address variable into which the IP
	 * address will be written if found
	 *
	 * \return Boolean indicating whether or not the IP address could be
	 * obtained (true) or not (false)
	 */
	bool getIpAddress(ICN_ID icnId, IP_ADDRESS &ipAddress);
	/*!
	 * \brief
	 *
	 * tba
	 *
	 * \param fqdn
	 *
	 * \return
	 */
	bool getFqdnIpAddressForIcnId(ICN_ID icnId, IP_ADDRESS &ipAddress);
	/*!
	 * \brief Retrieve ICN MTU
	 *
	 * This method returns the maxiaml number of bytes which can be added to an
	 * ICN (Blackadder) frame.
	 */
	int getIcnMtu();
	/*!
	 * \brief Retrieve IP MTU
	 *
	 * This method returns the MTU stored for the interface the NAP is
	 * communicating with its IP endpoints. If this value has not been changed
	 * via setMtu() it will always return the default value of 1492.
	 */
	int getIpMtu();
	/*!
	 * \brief
	 *
	 */
	bool getPacketFromAssemblyBuffer(string mapKey, uint8_t *packet);
	/*!
	 * \brief
	 *
	 * \param mapKey
	 */
	PACKET_LENGTH getPacketLengthFromAssemblyBuffer(string mapKey);
	/*!
	 * \brief Get the first packet in the ICN buffer for a given ICN ID
	 *
	 * This function walks through the packet buffer and writes the first
	 * packet destined for the given ICN ID to the reference variable.
	 *
	 * \param icnId The ICN ID for which the buffer should search for queued
	 * packets
	 * \param packet Pointer to write the packet into in case there is
	 * one in the queue
	 * \param timeStamp Pointer to timeStamp value when this packet was
	 * originally received
	 */
	void getPacketFromIcnBuffer(ICN_ID icnId, uint8_t *packet,
			boost::posix_time::ptime &timeStamp);
	/*!
	 * \brief Get the first packet in the IP buffer for a given IP address
	 *
	 * This function walks through the packet buffer and writes the first
	 * packet destined for the given IP address to the reference variable.
	 *
	 * \param ipAddress The IP address for which the buffer should search for
	 * queued packets
	 * \param packet Pointer to write the packet into in case there is
	 * one in the queue
	 * \param timeStamp Pointer to timeStamp value when this packet was
	 * originally received
	 */
	void getPacketFromIpBuffer(IP_ADDRESS ipAddress, uint8_t *packet,
			boost::posix_time::ptime *timeStamp);
	/*!
	 * \brief Returns the packet length of a queued packet
	 *
	 * This function looks up a given ICN ID in the packet buffer and returns
	 * it length. Note, in case multiple pakets have been buffered for the same
	 * ICN ID, this function always returns the length of the first packet in
	 * the buffer. Newly added packets for the same ICN ID do not affect the
	 * return value of this function, as buffer follows FIFO principle.
	 *
	 * \param icnId The ICN ID which should be looked up in the buffer
	 * \return The packet length of the first packet found in the buffer
	 */
	PACKET_LENGTH getPacketLength(ICN_ID icnId);
	/*!
	 * \brief Obtain the packet length for the first packet in queue
	 *
	 * This function looks up the IP buffer and returns the packet length for
	 * the first packet found in IP buffer matching the given IP address.
	 *
	 * \param ipAddress The IP address for which the IP buffer should be looked
	 * up
	 *
	 * \return The packet length of the packet in the IP buffer
	 */
	PACKET_LENGTH getPacketLength(IP_ADDRESS ipAddress);
	/*!
	 * \brief Find PID in HTTP ICN ID map
	 */
	PORT_IDENTIFIER getPortIdentifier(ICN_ID icnId);
	/*!
	 * \brief Obtain the routing prefix for a given ICN ID
	 *
	 * This function extracts the IP address from the ICN ID and looks up in the
	 * routingPrefixes map if the IP is known. If so, it writes the stored
	 * routing prefix into routingPrefix.
	 *
	 * \param icnId The ICN ID which should be looked up
	 * \param routingPrefix The corresponding routing prefix
	 *
	 * \return Boolean indicating whether reference variable has routing prefix
	 * (true) or not (false)
	 */
	bool getRoutingPrefix(ICN_ID icnId, ROUTING_PREFIX &routingPrefix);
	/*!
	 * \brief Obtain the routing prefix for a given IP address
	 *
	 * This function looks up the given IP address in the routingPrefixes map
	 * and returns the corresponding routing prefix.
	 *
	 * \param ipAddress The IP address which should be looked up
	 * \param routingPrefix Reference into which the routing prefix will be
	 * written
	 *
	 * \return Boolean indicating whether reference holds routing prefix (true)
	 * or not (false)
	 */
	bool getRoutingPrefix(IP_ADDRESS ipAddress, ROUTING_PREFIX &routingPrefix);
	/*!
	 * \brief Obtain the publication status of a scope path
	 *
	 * This function allows the NAP to obtain the current publication status
	 * of a particular scope path related to an ICN ID
	 *
	 * \param icnId The ICN ID for which the publication status should be
	 * checked
	 *
	 * \return Boolean indicating whether scope has been published (true) or
	 * not (false)
	 */
	bool getScopePublicationStatus(ICN_ID icnId);
	/*!
	 *
	 */
	TRANSPORT_KEY getTransportProtocolKey(ICN_ID icnId);
	/*!
	 * \brief Clean HTTP packet buffer
	 *
	 * This function checks the ICN buffer for packets older than PACKET_TIMEOUT
	 * defined in typedef.hh
	 */
	void httpPacketBufferCleaner();
	/*!
	 * \brief Cleaning ICN packet buffer
	 *
	 * This function checks the ICN buffer for packets older than PACKET_TIMEOUT
	 * defined in typedef.hh
	 */
	void icnPacketBufferCleaner();
	/*!
	 * \brief Cleaning IP packet buffer
	 *
	 * This function checks the IP buffer for packets older than PACKET_TIMEOUT
	 * defined in typedef.hh
	 */
	void ipPacketBufferCleaner();
	/*!
	 * \brief Check if IP address is IP endpoint of the NAP
	 *
	 * This function checks of a given IP address of format IP_ADDRESS is known
	 * as an IP endpoint of the NAP. The state about known IP endpoints is
	 * hold in the napIpEndpoints vector
	 *
	 * \param ipAddress The IP address which should be looked up
	 *
	 * \return True if the given IP address is an IP endpoint, false if not
	 */
	bool isIpEndpoint(IP_ADDRESS ipAddress);
	/*!
	 * \brief
	 *
	 * \param mapKey
	 */
	bool packetReassemblyPossible(string mapKey);
	/*!
	 * \brief Set forwarding policy
	 *
	 * This function sets the forwarding policy for a particular ICN ID. Note,
	 * the policy does not differentiate between inbound or outbound. The value
	 * stored in policy applies to both directions. In case it is set to false
	 * the NAP will store the packet temporarily
	 *
	 * \param icnId The ICN ID for which the policy should be set
	 * \param policy Boolean indicating whether an inbound or outbound packet
	 * is allowed to pass the NAP (true) or not (false)
	 */
	void setFwPolicy(ICN_ID icnId, bool policy);
	/*!
	 * \brief Set ICN MTU different from 1400
	 *
	 * This method changes the default MTU of the interface facing IP endpoints
	 * from 1492 to the value provided.
	 *
	 * \param mtu The new ICN MTU
	 */
	void setIcnMtu(int mtu);
	/*!
	 * \brief Set IP MTU different from 1492
	 *
	 * This method changes the default MTU of the interface facing IP endpoints
	 * from 1492 to the value provided.
	 *
	 * \param mtu The new IP MTU
	 */
	void setIpMtu(int mtu);
	/*!
	 * \brief Set the publication status of a scope path
	 *
	 * This function allows the NAP to keep track about what scope paths have
	 * been already published in order to reduce the required signalling for
	 * creating scopes
	 *
	 * \param icnId The ICN ID for which the scope publication status should be
	 * set
	 * \param status The status to be added to the database
	 */
	void setScopePublicationStatus(ICN_ID icnId, bool status);
	/*!
	 * \brief Test if the given IP matched the given routing prefix
	 *
	 * \param ipAddress The IP address which should be checked
	 * \param routingPrefix The routing prefix against which the IP address
	 * should be checked
	 *
	 * \return Boolean indicating whether IP matched prefix (true) or not
	 * (false)
	 */
	bool testIpAgainstRoutingPrefix(IP_ADDRESS ipAddress,
			ROUTING_PREFIX routingPrefix);
private:
#ifdef DEBUG
	log4cxx::LoggerPtr _logger;			/*!< Pointer to log4cxx instance */
#endif
	ICN_ID_DESCRIPTION_IP_MAP icnIdDescr;	/*!< ICN ID descriptions for
	namespace IP */
	ICN_ID_DESCRIPTION_HTTP_MAP icnIdDescriptionHttp; /*!< ICN ID description
	for namespace HTTP */
	ROUTING_PREFIX_VECTOR routingPrefixes; /*!< Vector of all known routing
											prefixes */
	IP_EUI48_MAP arpTable;				/*!< IP to MAC (EUI48) address mapping
											for ARP handler */
	IP_ADDRESS_VECTOR napIpEndpoints;		/*!< Vector storing all IP endpoints
											connected to this NAP */
	int _ipMtu = 1492; /*!< The MTU of the interface the NAP is communicating with
	IP endpoints */
	int _icnMtu = 1492; /*!< The maximal payload that can be added to an ICN
	(Blackadder) packet*/
	PACKET_BUFFER_ICN_DEQUE icnPacketBuffer;	/*!< Buffer which holds ICN
	packets waiting to be published to Blackadder */
	PACKET_BUFFER_IP_DEQUE ipPacketBuffer; /*!< Buffer which holds IP packets
	ready to be sent to one of the IP endpoints */
	PACKET_BUFFER_HTTP_DEQUE httpPacketBuffer; /*!< Buffer which holds HTTP
	content to be published */
	ASSEMBLY_BUFFER_MAP assemblyBuffer; /*!< Buffer holding fragmented packets*/
	COINCIDENTAL_MULTICAST_MAP coincidentalMulticast; /*!< Mapping Node IDs to
	identical URLs */
	boost::mutex mutexIpIcnIdDescription;		/*!< DB wide mutex to lock/unlock the
											ICN ID IP map */
	boost::mutex mutexHttpIcnIdDescription; /*!< DB mutex to lock/unlock HTTP
		description map */
	boost::mutex mutexIcnPacketBuffer;	/*!< DB wide mutex to lock/unlock the
	ICN packet buffer every time it is used	(enable transaction safe operation)*/
	boost::mutex mutexIpPacketBuffer;	/*!< DB wide mutex to lock/unlock the IP
	packet buffer every time it is used (enable transaction safe operations) */
	boost::mutex mutexHttpPacketBuffer;	/*!< DB wide mutex to lock/unlock the
	HTTP packet buffer every time it is used (enable transaction safe operations) */
	boost::mutex mutexAssemblyBuffer;/*!< DB wide mutex to lock/unlock
	the fragmented packet buffer every time it is used (enable transaction safe
	operation) */
	boost::mutex mutexArpTable;			/*!< DB mutex to lock/unlock content
	 	 	 	 	 	 	 	 	 	 changing operations on the ARP table */
	boost::mutex mutexNapIpEndpoints;	/*!< DB mutex to lock/unlock napClients
	 	 	 	 	 	 	 	 	 	 	 vector */
	boost::mutex mutexRoutingPrefixes;	/*!< DB mutex to lock/unlock routing
	prefix map */
	boost::mutex mutexCoincidentalMutlicast;	/*!< DB mutex to lock/unlock
	coincidental multicast map */
	BASE_GENERATOR_TYPE generator;		/*!< Boost number generator for random
											MAC addresses */
	/*!
	 * \brief Deleting the first found ICN packet from the ICN buffer
	 *
	 * This function deletes the first packet it can find for a given ICN ID
	 * from the buffer.
	 *
	 * \param icnId The ICN ID for which the first packet in the FIFO buffer
	 * should be deleted
	 */
	//void deletePacketFromIcnBuffer(ICN_ID icnId);
	/*!
	 * \brief Deleting the first found IP packet from the IP buffer
	 *
	 * This function deletes the first packet it can find for a given IP address
	 * from the buffer.
	 *
	 * \param ipAddress The IP address for which the first packet in the FIFO
	 * buffer should be deleted
	 */
	void deletePacketFromIpBuffer(IP_ADDRESS ipAddress);
	/*!
	 * \brief Generate random number
	 *
	 * This function is used by Database::generateEui48Address() to obtain a
	 * random number between start (0) and end (15) for the fake MAC address
	 * in response to an ARP request. The number generator (as indicated in the
	 * function name) follows a uniform distribution to generate a number.
	 *
	 * \param start The lower end of the range in which the generator should
	 * operate
	 * \param end The upper end of the range in which the generator should
	 * operate
	 * \return The generated number
	 */
	int generateUniformRandomNumber(int start, int end);
	/*!
	 * \brief Obtain a reference to the boost number generator
	 *
	 * This function returns a reference to the boost::minstd_rand generator
	 * for generating uniformly distributed integer numbers.
	 *
	 * \return The reference to the boost::minstd_rand generation of format
	 * BASE_GENERATOR_TYPE
	 */
	BASE_GENERATOR_TYPE &getGeneratorReference();
};

#endif /* DATABASE_HH_ */
