/*
 * iphandler.cc
 *
 *  Created on: 29 Apr 2015
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

#include "iphandler.hh"
#include "../helper.hh"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include "../transport.hh"

IpHandler::~IpHandler() {
	// TODO Auto-generated destructor stub
}

void IpHandler::operator()()
{
#ifdef DEBUG
#ifdef TRACE
	Transport transport(_nbBlackadder, _logger, _trace, _db);
#else
	Transport transport(_nbBlackadder, _logger, _db);
#endif
#else
#ifdef TRACE
	Transport transport(_nbBlackadder, _trace, _db);
#else
	Transport transport(_nbBlackadder, _db);
#endif
#endif
	Helper helper;
	ICN_ID icnId;
	string id, prefixId;
	/*if (_packetLength > MTU)
	{
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Dropping packet as it is larger than " << MTU);
#endif
		return;
	}*/
#ifdef TRACE
	_trace.writeTrace(_srcIpAddress, _dstIpAddress,	_dstPort, _packetLength);
#endif
	// New ICN ID
	if (!_db.getIcnId(_dstIpAddress, _dstPort, icnId))
	{
		ROUTING_PREFIX routingPrefix;
		if (!_db.getRoutingPrefix(_dstIpAddress, routingPrefix))
				return;
		icnId = helper.toIcnId(routingPrefix, _dstIpAddress, _dstPort);
		_db.addIcnId(icnId, _dstIpAddress, _dstPort, false);
	}
#ifdef DEBUG
	else
	{
		LOG4CXX_TRACE(_logger, "ICN ID for IP "
				<< helper.printIpAddress(_dstIpAddress) << " and port "
				<< _dstPort << " is " << helper.printIcnId(icnId));
	}
#endif
	// Packet for known ICN ID can be published
	if (_db.checkFwPolicy(icnId))
	{
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Forwarding policy for ICN ID "
				<< helper.printIcnId(icnId)
				<< " is enabled. Publishing data immediately");
#endif
		transport.sendPacket(icnId, _packet, _packetLength);
	}
	// Forwarding disabled for this ICN ID (no subscriber to previous packet)
	else
	{
		if (!_db.getScopePublicationStatus(icnId))
		{
			// Publish prefix scope
			id = helper.getScopeId(icnId, SCOPE_LEVEL_IP_PREFIX);
			prefixId = helper.getScopePath(icnId, SCOPE_LEVEL_IP_ROOT);
			_nbBlackadder->publish_scope(hex_to_chararray(id),
					hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL, 0);
#ifdef DEBUG
			LOG4CXX_DEBUG(_logger, "Published new prefix scope <"
					<< id << "> under root scope "
					<< helper.printScopePath(icnId, SCOPE_LEVEL_IP_ROOT));
#endif
			// Publish IP scope
			id = helper.getScopeId(icnId, SCOPE_LEVEL_IP_IPADDRESS);
			prefixId = helper.getScopePath(icnId, SCOPE_LEVEL_IP_PREFIX);
			_nbBlackadder->publish_scope(hex_to_chararray(id),
					hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL, 0);
#ifdef DEBUG
			LOG4CXX_DEBUG(_logger, "Published new IP scope <"
					<< id << "> under scope path "
					<< helper.printScopePath(icnId, SCOPE_LEVEL_IP_PREFIX));
#endif
			_db.setScopePublicationStatus(icnId, true);
		}
		_db.addPacketToIcnBuffer(icnId, _packet, _packetLength,
				_packetCaptureTimeStamp);
		// Advertise port information item under IP scope
		id = helper.getScopeId(icnId, SCOPE_LEVEL_IP_PORT);
		prefixId = helper.getScopePath(icnId, SCOPE_LEVEL_IP_IPADDRESS);
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Forwarding policy for information item <"
				<< id << "> under scope path "
				<< helper.printScopePath(icnId, SCOPE_LEVEL_IP_IPADDRESS)
				<< " is disabled. Buffer packet and advertise availability");
#endif
		_nbBlackadder->publish_info(hex_to_chararray(id),
				hex_to_chararray(prefixId),	DOMAIN_LOCAL, NULL, 0);
	}
}
