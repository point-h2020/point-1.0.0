/*
 * enumerations.hh
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

#ifndef ENUMERATIONS_HH_
#define ENUMERATIONS_HH_

/*!
 * \brief Port number declaration
 *
 * This enumeration list follows the IANA service port specification:
 * https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
 */
enum PortNumbers {
	PORT_UNKNOWN=0,			/*!< Only if transport layer protocol is unknown or raw IP packet has been received */
	PORT_FTP=21,			/*!< File Transfer Protocol */
	PORT_SSH=22,			/*!< The Secure Shell Protocol */
	PORT_DNS=53,			/*!< Domain Name Server */
	PORT_DHCP_SERVER=67,	/*!< Dynamic Host Configuration Protocol Server */
	PORT_DHCP_CLIENT=68,	/*!< Dynamic Host Configuration Protocol Client */
	PORT_HTTP=80,			/*!< World Wide Web HTTP */
	PORT_NETBIOS=137,				/*!< NETBIOS name service */
	PORT_HTTPS=443,			/*!< HTTP over TLS/SSL */
	PORT_COMMPLEX=5001,		/*!< IPERF */
	PORT_RTP_MEDIA=5004,	/*!< RTP media data */
	PORT_RTP_CONTROL=5005,	/*!< RPT control protocol */
	PORT_COAP=5683,			/*!< Constrained Application Protocol */
	PORT_COAPS=5684,		/*!< DTLS-secured CoAP */
	PORT_ICMP=5813			/*!< Internet Control Message Protocol */
};
/*!
 * \brief logging levels
 *
 * Re-enumeration from the Log4cxx library
 */
enum Log4cxxLevels {
	FATAL_INT = 50000,	/*!< fatal logging */
	ERROR_INT = 40000,	/*!< error logging and above */
	WARN_INT = 30000,	/*!< warning logging and above */
	INFO_INT = 20000,	/*!< info logging and above */
	DEBUG_INT = 10000,	/*!< debug logging and above */
	TRACE_INT = 5000	/*!< trace logging and above */
};
/*!
 * \brief ICN ID namespace levels (scope identifiers) for IPv4 over ICN
 *
 * This enumeration improves the readability of the class Helper when calling
 * the Helper::extractScopeId() member function
 */
enum ScopeLevelsIP {
	SCOPE_LEVEL_IP_ROOT=0,	/*!< Root scope (IP) */
	SCOPE_LEVEL_IP_PREFIX,	/*!< Hashed IP and netmask */
	SCOPE_LEVEL_IP_IPADDRESS,/*!< IP host address*/
	SCOPE_LEVEL_IP_PORT	/*!< Transport protocol port */
};
enum ScopeLevelsHttp {
	SCOPE_LEVEL_HTTP_ROOT=0,	/*!< Root scope (NAMESPACE_HTTP) */
	SCOPE_LEVEL_HTTP_FQDN,		/*!< Hashed FQDN */
	SCOPE_LEVEL_HTTP_FQDN_iITEM,/*!< iItem chunk of hashed FQDN (if any) */
	SCOPE_LEVEL_HTTP_URL,		/*!< Hashed URL */
	SCOPE_LEVEL_HTTP_URL_iITEM,	/*!< iItem chunk of hashed URL (if any) */
	SCOPE_LEVEL_HTTP_ANY,		/*!< Scope levels between root scope and iItem*/
	SCOPE_LEVEL_HTTP_ANY_iITEM	/*!< Last ID_LEN of given ICN ID */
};
/*!
 * \brief Root scope IDs (namespaces)
 *
 * This enumeration is used across all Blackadder core and application modules
 * to reduce the number of Level 1 scope IDs
 */
enum RootNamespaces {
	NAMESPACE_IP=0,				/*!< IP namespace */
	NAMESPACE_HTTP,				/*!< HTTP namespace */
	NAMESPACE_COAP,				/*!< COAP namespace */
	NAMESPACE_UNKNOWN			/*!< Unknown namespace */
};
/*!
 * \brief Customised netlink message types for inter process communications
 *
 * This enumeration extends struct nlmsghdr->nlmsg_type where NLMSG_NOOP,
 * NLMSG_ERROR, NLMSG_DONE, NLMSG_OVERRUN and NLMSG_MIN_TYPE are set in
 * netlink.h.
 */
enum NetlinkMessageTypes {
	/*!< Messages for proxy > NAP interactions */
	NAP_PROXY_HTTP_REQUEST=40,
	NAP_PROXY_HTTP_RESPONSE,
	/*!< Message for NAP > proxy interactions */
	PROXY_NAP_HTTP_REQUEST,
	PROXY_NAP_HTTP_RESPONSE
};
/*!
 * \brief Port Identifiers for Inter Process Communication
 *
 * The ports specified in this enumeration are used for IPCs between userspace
 * applications. In order to not interfere with any standardised PID (based on
 * IANA specification), the unassigned PID range 39682 - 39999 is used here.
 *
 * TODO implement proper PID bootstrapping where all applications utilise
 * getpid() through a multicast netlink group to distribute PID information.
 */
enum PortIdentifiers {
	PID_BLACKADDER=9999,
	/* NAP */
	PID_NAP_PROXY_LISTENER=39682,
	PID_NAP_PROXY_SENDER,
	PID_NAP_SENDER_HTTP_RESPONSE,
	PID_NAP_SENDER_HTTP_REQUEST,
	/* Proxy */
	PID_PROXY_NAP_LISTENER,
	PID_PROXY_LISTENER_HTTP_REQUEST,
	PID_PROXY_LISTENER_HTTP_RESPONSE,
	PID_PROXY_SENDER_HTTP_RESPONSE,
	PID_PROXY_SENDER_HTTP_REQUEST
};
/*!
 * \brief Enumeration of HTTP methods
 *
 * Those enumerations are taken from RFC 2616 and represent the different
 * methods used in requests and responses of the HTTP protocol. The declaration
 * is utilised by the NAP <> Squid API.
 *
 * Throughout the code the HTTP_METHOD type is used
 */
enum HttpMethods {
	/* Taken from section 9 in RFC 2616 */
	HTTP_METHOD_REQUEST_OPTIONS=0,
	HTTP_METHOD_REQUEST_GET,
	HTTP_METHOD_REQUEST_HEAD,
	HTTP_METHOD_REQUEST_POST,
	HTTP_METHOD_REQUEST_PUT,
	HTTP_METHOD_REQUEST_DELETE,
	HTTP_METHOD_REQUEST_TRACE,
	HTTP_METHOD_REQUEST_CONNECT,
	HTTP_METHOD_REQUEST_EXTENSION,
	/* Taken from section 10 in RFC 2616 */
	HTTP_METHOD_RESPONSE_CONTINUE=100,
	HTTP_METHOD_RESPONSE_SWITCHINGPROTOCOLS,
	HTTP_METHOD_RESPONSE_OK=200,
	HTTP_METHOD_RESPONSE_CREATED,
	HTTP_METHOD_RESPONSE_ACCEPTED,
	HTTP_METHOD_RESPONSE_NOCONTENT,
	HTTP_METHOD_RESPONSE_NOTFOUND=404,
	HTTP_METHOD_RESPONSE_REQUESTTIMEOUT=408,
	HTTP_METHOD_RESPONSE_BADGATEWAY=502,
	HTTP_METHOD_RESPONSE_SERVICEUNAVAILABLE,
	HTTP_METHOD_RESPONSE_GATEWAYTIMEOUT
};
// TODO come up with a better name
enum Types
{
	TYPE_FQDN,
	TYPE_URL,
	TYPE_RESOURCE
};
/*!
 * always use type TRANSPORT_STATE
 */
enum TransportStates {
	TRANSPORT_STATE_START=0,
	TRANSPORT_STATE_FRAGMENT,
	TRANSPORT_STATE_FINISHED,
	TRANSPORT_STATE_SINGLE_PACKET,
	TRANSPORT_STATE_UNKNOWN
};
/*!
 * Operations for Trace class
 */
enum Modes {
	MODE_SENT,
	MODE_RECEIVED
};
#endif /* ENUMERATIONS_HH_ */
