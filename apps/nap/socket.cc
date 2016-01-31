/*
 * socket.cc
 *
 *  Created on: 19 Jun 2015
 *      Author: Sebastian Robitzsch
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
#include "def.hh"
#include "socket.hh"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include "helper.hh"
Socket::~Socket() {
	libnet_destroy(_libnet);
}
bool Socket::createSocket(DEVICE *device)
{
	libnet_destroy(_libnet);
	char error[LIBNET_ERRBUF_SIZE];
	_libnet = libnet_init(LIBNET_LINK, device, error);
	if (_libnet == NULL)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Could not create socket on local "
				<< " interface '" << device << "'");
#endif
		return false;
	}
#ifdef DEBUG
	LOG4CXX_INFO(_logger, "Socket created on local interface '"
			<< device << "'");
#endif
	return true;
}

void Socket::fragmentAndSendPacket(EUI48 macAddressSource,
		EUI48 macAddressDestination, IP_ADDRESS ipAddressSource,
		IP_ADDRESS ipAddressDestination, PACKET *payload,
		PACKET_LENGTH payloadSize)
{
	u_int16_t ipHeaderId;
	Helper helper;
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *libnetRaw4;
	libnetRaw4 = libnet_init(LIBNET_RAW4, NULL, errbuf);
	if (libnetRaw4 == NULL) {
#ifdef DEBUG
		fprintf(stderr, "libnet_init() failed (raw4, 1st call): %s\n", errbuf);
#endif
		exit(EXIT_FAILURE);
	}
	/* headerOffset = fragmentation flags + offset (in bytes) divided by 8 */
	int payloadOffset = 0, headerOffset;
	int bytesWritten, maxIpPacketPayloadSize, ipPacketPayloadSize;
	libnet_ptag_t libnetReturnCode = LIBNET_PTAG_INITIALIZER;
	ipHeaderId = (u_int16_t)libnet_get_prand(LIBNET_PR16);
	/* Getting max payload size */
	maxIpPacketPayloadSize = (_db.getIpMtu() - LIBNET_IPV4_H);
	/* making it a multiple of 8 */
	maxIpPacketPayloadSize -= (maxIpPacketPayloadSize % 8);
	ipPacketPayloadSize = maxIpPacketPayloadSize;
	headerOffset = IP_MF;
	struct ip *ipHeader = (struct ip *)payload;
	// Skip the IP header as it is build by libnet
	payload += 4*ipHeader->ip_hl;
	// Remove the IP header length from the total length of the message to be
	// fragmented
	payloadSize -= 4*ipHeader->ip_hl;
	// calculate the payload of the transport
	if (libnet_build_ipv4((LIBNET_IPV4_H + maxIpPacketPayloadSize),
			ipHeader->ip_tos, ipHeaderId, headerOffset, ipHeader->ip_ttl,
			ipHeader->ip_p, 0, ipAddressSource, ipAddressDestination, payload,
			ipPacketPayloadSize, libnetRaw4, 0) == -1 )
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Error building fragmented IP header: "
				<< libnet_geterror(libnetRaw4));
#endif
		libnet_clear_packet(libnetRaw4);
		libnet_destroy(libnetRaw4);
		return;
	}
	bytesWritten = libnet_write(libnetRaw4);
	if (bytesWritten == -1)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "First IP fragment with ID "
				<< ipHeaderId << " has not been sent. Error: "
				<< libnet_geterror(libnetRaw4));
#endif
		libnet_clear_packet(libnetRaw4);
		libnet_destroy(libnetRaw4);
		return;
	}
#ifdef DEBUG
#ifdef TRACE /* DEBUG & TRACE */
	else
	{
		LOG4CXX_TRACE(_logger, "IP fragment with ID " << ipHeaderId
				<< ", offset " << headerOffset - IP_MF << " and size "
				<< ipPacketPayloadSize << " sent to "
				<< helper.printIpAddress(ipAddressDestination) << " ("
				<< ipPacketPayloadSize << "/" << payloadSize << " bytes sent)");
		_trace.writeTrace(MODE_SENT, ipAddressSource, ipAddressDestination,
				PORT_UNKNOWN, _db.getIpMtu(), ipHeaderId);
	}
#else /* DEBUG only */
	else
	{
		LOG4CXX_TRACE(_logger, "IP fragment with ID " << ipHeaderId
				<< ", offset " <<  headerOffset - IP_MF << " and size "
				<< ipPacketPayloadSize << " sent to "
				<< helper.printIpAddress(ipAddressDestination) << " ("
				<< ipPacketPayloadSize << "/" << payloadSize << " bytes sent)");
	}
#endif
#else
#ifdef TRACE /* TRACE only */
	else
	{
		_trace.writeTrace(MODE_SENT, ipAddressSource, ipAddressDestination,
				PORT_UNKNOWN, _db.getIpMtu(), ipHeaderId);
	}
#endif
#endif
	libnet_clear_packet(libnetRaw4);
	/* Now send off the remaining fragments */
	payloadOffset += ipPacketPayloadSize;
	while (payloadSize > payloadOffset)
	{
		/* Building IP header */
		/* checking if there will be more fragments */
		if ((payloadSize - payloadOffset) > maxIpPacketPayloadSize)
		{
			headerOffset = IP_MF + (payloadOffset)/8;
			ipPacketPayloadSize = maxIpPacketPayloadSize;
		}
		else {
			headerOffset = payloadOffset/8;
			ipPacketPayloadSize = payloadSize - payloadOffset;
		}
		libnetReturnCode =
				libnet_build_ipv4((LIBNET_IPV4_H + ipPacketPayloadSize), 0,
				ipHeaderId, headerOffset, ipHeader->ip_ttl, ipHeader->ip_p, 0,
				ipAddressSource, ipAddressDestination, (payload + payloadOffset),
				ipPacketPayloadSize, libnetRaw4, libnetReturnCode);
		if (libnetReturnCode == -1)
		{
#ifdef DEBUG
			LOG4CXX_ERROR(_logger, "Error building IP header for destination "
					<< helper.printIpAddress(ipAddressDestination) << ": "
					<< libnet_geterror(libnetRaw4));
#endif
			libnet_clear_packet(libnetRaw4);
			libnet_destroy(libnetRaw4);
			return;
		}
		bytesWritten = libnet_write(libnetRaw4);
		if (bytesWritten == -1)
		{
#ifdef DEBUG
			LOG4CXX_ERROR(_logger, "Error writing packet for IP destination "
					<< helper.printIpAddress(ipAddressDestination) << ": "
					<< libnet_geterror(libnetRaw4));
#endif
			libnet_clear_packet(libnetRaw4);
			libnet_destroy(libnetRaw4);
			return;
		}
#ifdef DEBUG
#ifdef TRACE /* DEBUG & TRACE */
		else
		{
			LOG4CXX_TRACE(_logger, "IP fragment with ID " << ipHeaderId
				<< ", offset " << headerOffset << " and size "
				<< ipPacketPayloadSize << " sent to "
				<< helper.printIpAddress(ipAddressDestination) << " ("
				<< payloadOffset + ipPacketPayloadSize << "/" << payloadSize
				<< " bytes sent)");
		_trace.writeTrace(MODE_SENT, ipAddressSource, ipAddressDestination,
				PORT_UNKNOWN, LIBNET_IPV4_H + ipPacketPayloadSize, ipHeaderId);
		}
#else /* DEBUG only */
#ifdef DEBUG
		else
		{
			LOG4CXX_TRACE(_logger, "IP fragment with ID " << ipHeaderId
				<< ", offset " << headerOffset << " and size "
				<< ipPacketPayloadSize << " sent to "
				<< helper.printIpAddress(ipAddressDestination) << " ("
				<< payloadOffset + ipPacketPayloadSize << "/" << payloadSize
				<< " bytes sent)");
		}
#else /* TRACE only */
		else
		{
			_trace.writeTrace(MODE_SENT, ipAddressSource, ipAddressDestination,
					PORT_UNKNOWN, LIBNET_IPV4_H + ipPacketPayloadSize, ipHeaderId);
		}
#endif
#endif
#endif
		/* Updating the offset */
		payloadOffset += ipPacketPayloadSize;
	}
	libnet_destroy(libnetRaw4);
}

void Socket::sendArpRequest(IP_ADDRESS ipAddressTarget)
{
	Helper helper;
	static libnet_ptag_t arp=0, eth=0;
	struct ether_addr *etherTarget;
	struct ether_addr *etherSrc;
	EUI48 eui48Src, eui48Target;
	static u_char ethSrc[6];
	static u_char ethTarget[6];
	static u_char ipSrc[4];
	static u_char ipDst[4];
	if (!_db.getEui48ForIp(_db.hostIpAddressDevice, eui48Src))
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "MAC address for host IP unknown!");
#endif
		return;
	}
	etherSrc = ether_aton(eui48Src.c_str());
	eui48Target = "ff:ff:ff:ff:ff:ff";
	etherTarget = ether_aton(eui48Target.c_str());
	memcpy(ethSrc, etherSrc, 6);
	memcpy(ethTarget, etherTarget, 6);
	memcpy(ipSrc, &_db.hostIpAddressDevice, 4);
	memcpy(ipDst, &ipAddressTarget, 4);
	mutexLibnet.lock();
	arp = libnet_autobuild_arp(ARPOP_REQUEST, ethSrc, ipSrc, ethTarget, ipDst,
			_libnet);
	if (arp == -1)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "ARP request autobuild failed due to "
				<< libnet_geterror(_libnet));
#endif
		libnet_clear_packet(_libnet);
		mutexLibnet.unlock();
		return;
	}
	// Building Ethernet packet
	eth = libnet_build_ethernet(ethTarget, ethSrc, ETHERTYPE_ARP, NULL, 0,
			_libnet, 0);
	if (eth == -1)
	{
#ifdef DEBUG
		LOG4CXX_ERROR (_logger, "Ethernet frame build for ARP reply failed: "
				<< libnet_geterror(_libnet));
#endif
		libnet_clear_packet(_libnet);
		mutexLibnet.unlock();
		return;
	}
	if (libnet_write(_libnet) == -1)
	{
#ifdef DEBUG
		LOG4CXX_ERROR (_logger, "Could not send ARP request asking for MAC of "
				<< helper.printIpAddress(ipAddressTarget) << " due to "
				<< libnet_geterror(_libnet));
#endif
		libnet_clear_packet(_libnet);
		mutexLibnet.unlock();
		return;
	}
	libnet_clear_packet(_libnet);
	mutexLibnet.unlock();
#ifdef TRACE
	_trace.writeTrace(MODE_SENT, ARPOP_REQUEST, _db.hostIpAddressDevice,
					ipAddressTarget, eui48Src, eui48Target);
#endif
#ifdef DEBUG
	LOG4CXX_TRACE(_logger, "ARP request sent asking for "
			<< helper.printIpAddress(ipAddressTarget) << "'s MAC address");
#endif
}

void Socket::sendPacket(PACKET *packet, PACKET_LENGTH packetLength)
{
	Helper helper;
	static libnet_ptag_t eth=0;
	static u_char eth_src[6];
	static u_char eth_dst[6];
	struct ip *ipHeader;
	IP_ADDRESS ipAddressSrc, ipAddressDst;
	EUI48 macAddrSrc, macAddrDst;
	PACKET *p;
	ipHeader = (struct ip *)packet;
	if (_libnet == NULL)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Socket not open");
#endif
		return;
	}
	ipAddressSrc = ipHeader->ip_src.s_addr;
	if (!_db.getEui48ForIp(ipAddressSrc, macAddrSrc))
	{
		_db.getEui48ForIp(_db.hostIpAddressDevice, macAddrSrc);
		_db.addIpEui48Pair(ipAddressSrc, macAddrSrc);
	}
	ipAddressDst = ipHeader->ip_dst.s_addr;
	if (!_db.getEui48ForIp(ipAddressDst, macAddrDst))
	{
#ifdef DEBUG
		LOG4CXX_DEBUG(_logger, "Unable to find MAC address for IP "
				<< helper.printIpAddress(ipAddressDst) << ". Issue ARP REQ");
#endif
		_db.addPacketToIpBuffer(ipAddressDst, packet, packetLength);
		sendArpRequest(ipAddressDst);
		return;
	}
	// Fragment IP packet in case it's larger than MTU (defined in typedef.hh)
	if (packetLength > _db.getIpMtu())
	{
		fragmentAndSendPacket(macAddrSrc, macAddrDst, ipAddressSrc,
				ipAddressDst, packet, packetLength);
		return;
	}
	memcpy(eth_src, ether_aton(macAddrSrc.c_str()), 6);
	memcpy(eth_dst, ether_aton(macAddrDst.c_str()), 6);
	p = (PACKET *)malloc(packetLength);
	memcpy(p, packet, packetLength);
	mutexLibnet.lock();
	eth = libnet_build_ethernet(eth_dst, eth_src, ETHERTYPE_IP, p,
			packetLength, _libnet, 0);
	if (eth < 0)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Failed to create Ethernet packet with IP "
				<< "packet as payload. Error: " << libnet_geterror(_libnet));
#endif
		libnet_clear_packet(_libnet);
		mutexLibnet.unlock();
		return;
	}
	if (libnet_write(_libnet) < 0)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Failed to send Ethernet packet with IP packet "
				<< "of length " << packetLength << ". Error: "
				<< libnet_geterror(_libnet));
#endif
		libnet_clear_packet(_libnet);
		mutexLibnet.unlock();
		return;
	}
	libnet_clear_packet(_libnet);
	mutexLibnet.unlock();
#ifdef TRACE
	_trace.writeTrace(ipAddressSrc, ipAddressDst, "-", packetLength,
			boost::posix_time::microsec_clock::local_time());
#endif
#ifdef DEBUG
	LOG4CXX_TRACE(_logger, "Ethernet packet with IP packet as payload (length "
			<< packetLength << ") was sent to IP endpoint "
			<< helper.printIpAddress(ipAddressDst));
#endif
}
