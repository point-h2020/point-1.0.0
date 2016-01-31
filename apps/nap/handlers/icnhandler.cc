/*
 * icnhandler.cc
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

#include "icnhandler.hh"
#include "../helper.hh"
#ifdef TRACE
#include "../trace.hh"
#endif
#include "../transport.hh"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ether.h>

IcnHandler::~IcnHandler() {
	// TODO Auto-generated destructor stub
}

void IcnHandler::operator()() {
	ICN_ID icnId;
	Helper helper;
	boost::posix_time::time_duration timeDuration;
	boost::posix_time::ptime timeStamp;
	switch (_ev->type) {
	case SCOPE_PUBLISHED:
	{
		string id, prefixId;
		icnId = chararray_to_hex(_ev->id);

		switch(helper.getRootId(icnId))
		{
		case NAMESPACE_IP:
		{
#ifdef DEBUG
			LOG4CXX_DEBUG(_logger, "SCOPE_PUBLISHED event received for ICN ID "
					<< helper.printIcnId(icnId) << " (IP namespace)");
#endif
			ROUTING_PREFIX routingPrefix;
			EUI48 eui48;
			if (!_db.getRoutingPrefix(icnId, routingPrefix))
				return;
			icnId = helper.toIcnId(routingPrefix, helper.getIpAddress(icnId),
					PORT_UNKNOWN);
			if (!_db.findIcnId(icnId))
			{
				_db.addIcnId(icnId);
				_db.setScopePublicationStatus(icnId, true);
			}
			id = helper.getScopeId(icnId, SCOPE_LEVEL_IP_IPADDRESS);
			prefixId = helper.getScopePath(icnId, SCOPE_LEVEL_IP_PREFIX);
			if (!_db.getEui48ForIp(helper.getIpAddress(icnId), eui48))
			{
#ifdef DEBUG
				LOG4CXX_DEBUG(_logger, "MAC address for destination IP "
						<< helper.printIpAddress(helper.getIpAddress(icnId))
						<< " is unknown");
#endif
				_rawSocket.sendArpRequest(helper.getIpAddress(icnId));
			}
			break;
		}
		/*
		 * this case occurs when hashed FQDN or URL is longer than ID_LEN
		 */
		case NAMESPACE_HTTP:
		{
#ifdef DEBUG
			LOG4CXX_DEBUG(_logger, "SCOPE_PUBLISHED event received for ICN ID "
					<< helper.printIcnId(icnId) << " (HTTP namespace)");
#endif
			_db.addIcnId(icnId);
			_db.setScopePublicationStatus(icnId, true);
			// Assuming all IDs are of length ID_LEN
			id = helper.getScopeId(icnId, SCOPE_LEVEL_HTTP_ANY_iITEM);
			prefixId = helper.getScopeId(icnId, SCOPE_LEVEL_HTTP_ANY);
		}
		default:
		{
#ifdef DEBUG
			LOG4CXX_ERROR(_logger, "SCOPE_PUBLISHED event received for ICN ID "
					<< helper.printIcnId(icnId) << ". Unknown namespace");
#endif
			return;
		}
		}
#ifdef DEBUG
		ostringstream oss;
		oss << prefixId << id;
		LOG4CXX_DEBUG(_logger, "Subscribing to scope path "
				<< helper.printIcnId(oss.str()));
#endif
		_nbBlackadder->subscribe_scope(hex_to_chararray(id),
				hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL, 0);
		break;
	}
	case SCOPE_UNPUBLISHED:
	{
		icnId = chararray_to_hex(_ev->id);
#ifdef DEBUG
		LOG4CXX_DEBUG(_logger, "SCOPE_UNPUBLISHED event received for ICN ID "
				<< helper.printIcnId(icnId));
#endif
		_db.deleteIcnId(icnId);
		break;
	}
	case START_PUBLISH:
	{
		string prefixId;
#ifdef DEBUG /* DEBUG start */
#ifdef TRACE /* TRACE start */
		Transport transport(_nbBlackadder, _logger, _trace, _db);
#else
		Transport transport(_nbBlackadder, _logger, _db);
#endif /* TRACE end */
#else /* DEBUG else */
#ifdef TRACE /* TRACE start */
		Transport transport(_nbBlackadder, _trace, _db);
#else
		Transport transport(_nbBlackadder, _db);
#endif /* TRACE end */
#endif /* DEBUG end */
		icnId = chararray_to_hex(_ev->id);
		switch(helper.getRootId(icnId))
		{
		case NAMESPACE_IP:
		{
#ifdef DEBUG
			LOG4CXX_DEBUG(_logger, "START_PUBLISH event received for ICN ID "
					<< helper.printIcnId(icnId) << ". Checking IP buffer for "
					<< "packets");
#endif
			while (_db.checkForPacketInIcnBuffer(icnId))
			{
				PACKET *packet;
				PACKET_LENGTH packetLength;
				packetLength = _db.getPacketLength(icnId);
				packet = reinterpret_cast<PACKET *>(malloc(packetLength + 1));
				_db.getPacketFromIcnBuffer(icnId, packet, timeStamp);
				transport.sendPacket(icnId, packet, packetLength);
			}
			break;
		}
		case NAMESPACE_HTTP:
		{
			ICN_ID icnIdUrl;
#ifdef DEBUG
			LOG4CXX_DEBUG(_logger, "START_PUBLISH event received for ICN ID "
					<< helper.printIcnId(icnId) << ". Checking ICN buffer for "
					<< "HTTP packets");
#endif
			if(!_db.getIcnIdUrl(icnId, icnIdUrl))
			{
#ifdef DEBUG
				LOG4CXX_ERROR(_logger, "URL for ICN ID "
						<< helper.printIcnId(icnId) << " could not be obtained");
#endif
				break;
			}
			while (_db.checkForPacketInIcnBuffer(icnId))
			{
				uint8_t *packet;
				size_t packetLength = _db.getPacketLength(icnId);
				TRANSPORT_KEY key = _db.getTransportProtocolKey(icnId);
				packet = (uint8_t *)malloc(packetLength);
				_db.getPacketFromIcnBuffer(icnId, packet, timeStamp);
				transport.publishDataiSub(icnId, icnIdUrl, key, packet,
						packetLength, timeStamp);
			}
			break;
		}
#ifdef DEBUG
		default:
			LOG4CXX_ERROR(_logger, "START_PUBLISH event received for ICN ID "
					<< helper.printIcnId(icnId) << ". Unknown root namespace!");
#endif
		}
		_db.setFwPolicy(icnId, true);
		break;
	}
	case STOP_PUBLISH:
	{
		icnId = chararray_to_hex(_ev->id);
#ifdef DEBUG
		LOG4CXX_DEBUG(_logger, "STOP_PUBLISH event received for ID "
						<< helper.printIcnId(icnId));
#endif
		_db.setFwPolicy(icnId, false);
		break;
	}
	case PUBLISHED_DATA:
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
		icnId = chararray_to_hex(_ev->id);
		switch (helper.getRootId(icnId))
		{
		case NAMESPACE_IP:
		{
#ifdef DEBUG
			LOG4CXX_TRACE(_logger, "PUBLISHED_DATA (IP) of length "
					<< _ev->data_len << " received from ICN core under ICN ID "
					<< helper.printIcnId(icnId));
#endif
			transport.assemblePacket(_rawSocket, icnId, _ev->data, _ev->data_len);
			break;
		}
		case NAMESPACE_HTTP:
		{
#ifdef DEBUG
			LOG4CXX_TRACE(_logger, "PUBLISHED_DATA (HTTP) of length "
					<< _ev->data_len << " received from ICN core under ICN ID "
					<< helper.printIcnId(icnId));
#endif
			if (!_db.findIcnId(icnId))
			{
#ifdef DEBUG
				LOG4CXX_ERROR(_logger, "Unknown ICN ID "
						<< helper.printIcnId(icnId));
#endif
				break;
			}
			transport.assemblePacket(_rawSocket, icnId, _ev->data, _ev->data_len);
			break;
		}
#ifdef DEBUG
		default:
			LOG4CXX_ERROR(_logger, "Unknown ICN namespace");
#endif
		}
		break;
	}
	/*case PUBLISHED_DATA_iSUB:
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
		ICN_ID icnId = chararray_to_hex(_ev->id);
		ICN_ID iSubIcnId = chararray_to_hex(_ev->isubID);
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "PUBLISHED_DATA_iSUB received of length "
				<< _ev->data_len << " from ICN core under ICN ID "
				<< helper.printIcnId(icnId) << " including implicit "
				<< "subscription for ICN ID " << helper.printIcnId(iSubIcnId));
#endif
		// Publishing implicit subscription scope path
		// Creating HTTP root scope and publish URL
		if (!_db.findIcnId(iSubIcnId))
		{
			_db.addIcnId(iSubIcnId, TYPE_URL);
			string prefixId = helper.getScopeId(iSubIcnId, SCOPE_LEVEL_HTTP_ROOT);
			string id = helper.getScopeId(iSubIcnId, SCOPE_LEVEL_HTTP_URL);
			if (id.size() > ID_LEN)
			{
#ifdef DEBUG
				LOG4CXX_DEBUG(_logger, "Chunk the hashed URL "
						<< helper.printIcnId(iSubIcnId) << " into: "
						<< helper.printIcnId(id));
#endif
				for (size_t chunk = 0; chunk < (id.size() / ID_LEN); chunk++)
				{
					ostringstream oss;
					for (size_t it = 0; it < ID_LEN; it++)
					{
						oss << id[chunk * ID_LEN + it];
					}
					if (chunk != (id.size() / ID_LEN - 1))
					{
#ifdef DEBUG
						LOG4CXX_DEBUG(_logger, "Publish URL scope "
								<< helper.printIcnId(oss.str())
								<< " under HTTP father scope "
								<< helper.printIcnId(prefixId));
#endif
						_nbBlackadder->publish_scope(
								hex_to_chararray(oss.str()),
								hex_to_chararray(prefixId), DOMAIN_LOCAL,
								NULL, 0);
					}
					prefixId.append(oss.str());
				}
				prefixId = helper.getScopePath(iSubIcnId, SCOPE_LEVEL_HTTP_URL);
				id = helper.getScopeId(iSubIcnId, SCOPE_LEVEL_HTTP_URL_iITEM);
#ifdef DEBUG
				LOG4CXX_DEBUG(_logger, "Advertising iItem "
						<< helper.printIcnId(id) << " under HTTP father scope "
						<< helper.printIcnId(prefixId));
#endif
				_nbBlackadder->publish_info(hex_to_chararray(id),
						hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL, 0);
			}
#ifdef DEBUG
			else
			{
				LOG4CXX_ERROR(_logger, "Strange, URL is 16 digits long?!?!?!");
			}
#endif
			_db.setScopePublicationStatus(iSubIcnId, true);
			_db.setFwPolicy(iSubIcnId, true);
		}
		transport.assemblePacket(icnId, iSubIcnId, _ev->nodeId,
				_ev->data, _ev->data_len);
		break;
	}*/
#ifdef DEBUG
	default:
		LOG4CXX_DEBUG(_logger, "Unknown Blackadder event received");
#endif
	}
}

