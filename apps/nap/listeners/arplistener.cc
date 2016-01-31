/*
 * arplistener.cc
 *
 *  Created on: 4 Jun 2015
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

#include "arplistener.hh"
#include "../helper.hh"
#include "../database.hh"
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ether.h>


ArpListener::~ArpListener() {
	libnet_destroy(libnet);
}

void ArpListener::operator()()
{
	struct arphdr *arpHeader;
	struct ether_arp *arpPacket;
	arpPacket = (struct ether_arp *) _packet;
	ostringstream oss;
	IP_ADDRESS ipAddressTarget, ipAddressSender;
	EUI48 eui48Sender, eui48Target;
	Helper helper;
	struct in_addr address;
	arpHeader = (struct arphdr *) _packet;
	if (ntohs(arpHeader->ar_op) == ARPOP_REQUEST)
	{

		eui48Sender = ether_ntoa((struct ether_addr *)&arpPacket->arp_sha);
		address = *(struct in_addr *)arpPacket->arp_spa;
		ipAddressSender = address.s_addr;
		address = *(struct in_addr *)arpPacket->arp_tpa;
		ipAddressTarget = address.s_addr;
		if (ipAddressSender == _db.hostIpAddressDevice)
		{
#ifdef DEBUG
			LOG4CXX_TRACE(_logger, "Ignoring ARP request sent by local machine "
					<< "(IP " << helper.printIpAddress(_db.hostIpAddressDevice)
					<< ") to ask for MAC of "
					<< helper.printIpAddress(ipAddressTarget));
#endif
			return;
		}
#ifdef TRACE
		_trace.writeTrace(ipAddressSender, ipAddressTarget, eui48Sender);
#endif
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "ARP request packet captured: " << "Who has "
				<< helper.printIpAddress(ipAddressTarget) << "? Tell "
				<< helper.printIpAddress(ipAddressSender) << " ("
				<< eui48Sender << ")");
#endif
		_db.addIpEui48Pair(ipAddressSender, eui48Sender);
		if (!_db.getEui48ForIp(ipAddressTarget, eui48Target))
		{
			_db.addIpEui48Pair(ipAddressTarget, _db.generateEui48Address());
			_db.getEui48ForIp(ipAddressTarget, eui48Target);
		}
		static u_char eth_src[6];
		static u_char eth_dst[6];
		static u_char ip_src[4];
		static u_char ip_dst[4];
		if (libnet == NULL)
		{
#ifdef DEBUG
			LOG4CXX_ERROR(_logger, "ARP socket on local interface "	<< _device
					<< " is not available");
#endif
			return;
		}
		memcpy(ip_dst, &ipAddressSender, 4);
		memcpy(ip_src, &ipAddressTarget, 4);
		memcpy(eth_src, ether_aton(eui48Target.c_str()), 6);
		memcpy(eth_dst, ether_aton(eui48Sender.c_str()), 6);
		static libnet_ptag_t arp=0, eth=0;
		// Building ARP packet
		arp = libnet_autobuild_arp(ARPOP_REPLY, eth_src, ip_src, eth_dst,
				ip_dst, libnet);
		if (arp == -1)
		{
#ifdef DEBUG
			LOG4CXX_ERROR(_logger, "ARP reply autobuild failed due to "
					<< libnet_geterror(libnet)
					<< "Trying to build ARP reply manually");
#endif
			arp = libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, ETH_ALEN, 4,
						ARPOP_REPLY, eth_src, ip_src, eth_dst, ip_dst, NULL, 0,
						libnet,	0);
			if (arp == -1)
			{
#ifdef DEBUG
				LOG4CXX_ERROR(_logger, "Also failed due to "
						<< libnet_geterror(libnet));
#endif
				return;
			}
		}
		// Building Ethernet packet
		eth = libnet_build_ethernet(eth_dst, eth_src, ETHERTYPE_ARP, NULL, 0,
				libnet, 0);
		if (eth == -1)
		{
#ifdef DEBUG
			LOG4CXX_ERROR (_logger, "Ethernet frame build for ARP reply failed: "
					<< libnet_geterror(libnet)
					<< ". Trying to build it using autobuild");
#endif
			eth = libnet_autobuild_ethernet(eth_dst, ETHERTYPE_ARP, libnet);
			if (eth == -1)
			{
#ifdef DEBUG
				LOG4CXX_ERROR (_logger, "Also failed due to "
						<< libnet_geterror(libnet));
#endif
				return;
			}
		}
		if (libnet_write(libnet) == -1)
		{
#ifdef DEBUG
			LOG4CXX_ERROR (_logger, "Could not send ARP reply due to "
					<< libnet_geterror(libnet));
#endif
			return;
		}
#ifdef TRACE
		_trace.writeTrace(ipAddressTarget, ipAddressSender, eui48Target,
				eui48Sender, _packetCaptureTimeStamp);
#endif
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "ARP reply sent to "
				<< helper.printIpAddress(ipAddressSender)
				<< " (" << eui48Sender << "): "
				<< helper.printIpAddress(ipAddressTarget) << " is at "
				<< eui48Target);
#endif
	}
	else if (ntohs(arpHeader->ar_op) == ARPOP_REPLY)
	{
		PACKET_LENGTH packetLength;
		boost::posix_time::ptime timeStamp;
		eui48Sender = ether_ntoa((struct ether_addr *)&arpPacket->arp_sha);
		eui48Target = ether_ntoa((struct ether_addr *)&arpPacket->arp_tha);
		address = *(struct in_addr *)arpPacket->arp_spa;
		ipAddressSender = address.s_addr;
		address = *(struct in_addr *)arpPacket->arp_tpa;
		ipAddressTarget = address.s_addr;
		if (ipAddressSender == _db.hostIpAddressDevice)
			return;
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "ARP reply packet captured: "
				<< helper.printIpAddress(ipAddressSender) << " is at "
				<< eui48Sender);
#endif
#ifdef TRACE
		_trace.writeTrace(MODE_RECEIVED, ARPOP_REPLY, ipAddressSender,
				ipAddressTarget, eui48Sender, eui48Target);
#endif
		_db.addIpEui48Pair(ipAddressSender, eui48Sender);
		while (_db.checkForPacketInIpBuffer(ipAddressSender))
		{
			packetLength = _db.getPacketLength(ipAddressSender);
			uint8_t *packet = reinterpret_cast<uint8_t *>(malloc(packetLength));
			_db.getPacketFromIpBuffer(ipAddressSender, packet, &timeStamp);
			_rawSocket.sendPacket(packet, packetLength);
		}
	}
}
