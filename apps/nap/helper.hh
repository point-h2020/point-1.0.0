/*
 * helper.hh
 *
 *  Created on: 30 Apr 2015
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
#include "typedef.hh"

#ifndef HELPER_HH_
#define HELPER_HH_
/*! \brief Converting information into other formats
 *
 * This helper class will serve as a stateless entity which provides member
 * functions to convert a piece of information into different formats, e.g.:
 * - IP address to ICN ID and vice versa
 * - IP address and port number to ICN ID and vice versa
 * - URL (FQDN + tail) to ICN ID
 */
class Helper {
public:
	/*!
	 * Constructor
	 */
	Helper();
	/*!
	 * Deconstructor
	 */
	~Helper();
	/*!
	 * \brief Obtain IP address from given ICN ID
	 *
	 * This function follows the IP-over-ICN routing prefix abstraction where
	 * the third scope level comprises the IP address. The helper function
	 * simply extracts this information from the given ICN ID.
	 *
	 * \param icnId The ICN ID from which the IP address should be extracted
	 *
	 * \return The extracted IP address is return
	 */
	IP_ADDRESS getIpAddress(ICN_ID icnId);
	/*!
	 * \brief Extracting scope identifier from given ICN ID
	 *
	 * This function extracts the scope ID for a given ICN ID and the
	 * corresponding scope level. When using the IP namespace
	 * the scope level defined in struct ScopeLevelsIPv4 is used
	 *
	 * \param icnId The full scope ICN ID as stored in the NAP DB
	 * \param scopeLevel The scope level for which the function will compute the scope ID using enumeration ScopeLevelsIPv4
	 * \return the scope identifier in format ICN_ID (multiple of ID_LEN)
	 */
	ICN_ID getScopeId(ICN_ID icnId, uint16_t scopeLevel);
	/*!
	 * \brief Retrieve the scope path
	 *
	 * This function converts a given ICN ID into a scope path using the
	 * scope level provided as the second argument
	 *
	 * \param icnId The ICN ID for which the scope path should be obtained
	 * \param scopeLevel The scope level which identifies the depth desired
	 * \return The scope path is return as the output of this function
	 */
	ICN_ID getScopePath(ICN_ID icnId, uint16_t scopeLevel);
	/*!
	 * \brief Returning the root namespace of a given ICN ID
	 *
	 * This function returns the root namespace of a given ICN ID, as defined
	 * in enumeration.hh.
	 *
	 * \param icnId The ICN ID which should be analysed
	 *
	 * \return The namespace enumeration
	 */
	uint16_t getRootId(ICN_ID icnId);
	/*!
	 * \brief Converting MAC address (ASCII) to EUI48 (HEX string)
	 *
	 * This function convert the output of ether_ntoa to a string representation
	 * which can be directly used as an ICN ID.
	 *
	 * \param mac The mac address which should be converted
	 * \return The MAC address of an interface in format ICN_ID
	 */
	EUI48 macToEui48(char * mac);
	/*!
	 * \brief Print the ICN ID in a more human readable format
	 *
	 * This helper prints the ICN ID in a human readable format by automatically
	 * obtaining the used root scope namespace. The format follows standard ICN
	 * scope representation, i.e.: /rootScope/ScopeLevel1/ScopeLevel2/...
	 *
	 * \param icnId The ICN ID which should be printed
	 *
	 * \return The ICN ID in a more human readable format
	 */
	string printIcnId(ICN_ID icnId);
	/*!
	 * \brief Prints an EUI48 address in human readable format
	 *
	 * This function takes an EUI48 address of format ICN ID and creates a
	 * human readable format using semicolons.
	 *
	 * \param eui48 The EUI48 address which should be converted
	 * \return The human readable format of the given EU48 address
	 */
	string printEui48(EUI48 eui48);
	/*!
	 * \brief IP address conversation from bytes to ASCII
	 */
	string printIpAddress(IP_ADDRESS ipAddress);
	/*!
	 * \brief Netmask conversation from bytes to ASCII
	 */
	string printNetmask(NETMASK netmask);
	/*!
	 * \brief Printing a transport layer port
	 *
	 * This function translates the network order byte representation of a
	 * transport layer port into a decimal-based string representation
	 *
	 * \param port The port in network byte order
	 *
	 * \return Decimal-based string representation of the given port
	 */
	string printPort(PORT port);
	/*!
	 * \brief Printing a routing prefix in human readable format
	 *
	 * This function takes a routing prefix and prints out the IP address and
	 * the corresponding netmask using the format 64.62.0.0/255.255.0.0
	 *
	 * \param routingPrefix The routing prefix struct which holds the IP address
	 * and the netmask
	 *
	 * \return Decimal-based string representation of the routing prefix
	 */
	string printRoutingPrefix(ROUTING_PREFIX routingPrefix);
	/*!
	 * \brief Printing the scope path in a human readable format
	 *
	 * This function prints the scope path for any ICN abstraction implemented
	 * in this NAP using "/" as a scope level separator. The depth of the scope
	 * which should be printed must be provided as the second argument
	 *
	 * \param icnId The ICN ID which should be printed
	 * \param scopeLevel The levels of scopes which should be printed using the
	 * ScopeLevels<ABSTRACTION> enum in enumerations.hh
	 *
	 * \return String-based scope path
	 */
	string printScopePath(ICN_ID icnId, uint8_t scopeLevel);
	/*!
	 * \brief Generating ICN ID from IP and port
	 *
	 * This function takes a given IPv4 address + port number and generates an
	 * ICN ID of format: RS/NA/AABBCCDDPPPP where RS stands for Root Scope and
	 * NA for the name space (defined in RootScopes struct); AA represents the
	 * IP for Class A, BB for Class C and DD for Class D in hexadecimal 2-digit
	 * format. PPPP represents the port number in hexadecimal format. In case
	 * the port is UNKNOWN (no transport layer protocol used), the sub-scope
	 * PPPP is set to '0000'.
	 *
	 * \param routingPrefix The routing prefix definition (IP + netmask)
	 * \param ipAddress The host IP address
	 * \param port The IP of the IP endpoint which forms part of the ICN ID
	 * \return This function returns the ICN ID of length % ID_LEN = 0
	 */
	ICN_ID toIcnId(ROUTING_PREFIX routingPrefix, IP_ADDRESS ipAddress,
			PORT port);
	/*!
	 * \brief Convert a URL to an ICN ID
	 *
	 * Convert either an FQDN or resource to a unique ICN ID using the HTTP
	 * method to distinguish between the two.
	 *
	 * \param icnNamespace The ICN namespace used
	 * \param str The FQDN or the URL's resource
	 *
	 * \return The ICN Identifier
	 */
	ICN_ID toIcnId(uint16_t icnNamespace, string str);
	/*!
	 * \brief
	 *
	 * TBA
	 *
	 * \param icnId
	 */
	string toMapKey(ICN_ID icnId, TRANSPORT_KEY key);
	/*!
	 * \brief
	 *
	 * TBA
	 *
	 * \param icnId
	 */
	string toMapKey(ICN_ID icnId, string nodeId, TRANSPORT_KEY key);
};

#endif /* HELPER_HH_ */
