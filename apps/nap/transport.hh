/*
 * transport.hh
 *
 *  Created on: Oct 4, 2015
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

#ifndef NAP_TRANSPORT_HH_
#define NAP_TRANSPORT_HH_

#include "database.hh"
#ifdef DEBUG
#include <log4cxx/logger.h>
#endif
#include <nb_blackadder.hpp>
#ifdef TRACE
#include "trace.hh"
#endif
#include "typedef.hh"
#include "socket.hh"

class Transport {
public:
	/*!
	 * \brief Constructor
	 */
	Transport(NB_Blackadder *nbBlackadder,
#ifdef DEBUG
			log4cxx::LoggerPtr logger,
#endif
#ifdef TRACE
			Trace &trace,
#endif
			Database &db)
	: _nbBlackadder(nbBlackadder),
#ifdef DEBUG
	  _logger(logger),
#endif
#ifdef TRACE
	  _trace(trace),
#endif
	  _db(db)
	  { }
	/*!
	 * \brief Deconstructor
	 */
	~Transport();
	/*!
	 * \brief Add received response packet
	 */
	void assemblePacket(Socket &socket, ICN_ID icnId, void *icnPacketPayload,
			PACKET_LENGTH icnPacketPayloadLength);
	/*!
	 * \brief Add received HTTP request packet
	 *
	 * \param icnId
	 * \param iSubIcnId
	 * \param nodeId
	 * \param icnPacketPayload
	 * \param icnPacketPayloadLength
	 */
	void assemblePacket(ICN_ID icnId, ICN_ID iSubIcnId, string nodeId,
			void *icnPacketPayload, PACKET_LENGTH icnPacketPayloadLength);
	/*!
	 * \brief Implementation of PROXY_FORWARD_PACKET primitive
	 *
	 * The NAP sends a packet to the proxy which shall be forwarded to the IP
	 * endpoint
	 *
	 * \param ipAddress
	 * \param reassembledPacket
	 * \param reassembledPacketLength
	 *
	 *///TODO create HTTP proxy API in NAP and put this class to there
	void proxyNapHttpRequest(IP_ADDRESS ipAddress,
			PACKET *reassembledPacket, PACKET_LENGTH reassembledPacketLength);
	/*!
	 * \brief
	 *
	 * \param portIdentifier
	 * \param packet
	 * \param packetLength
	 *///TODO create HTTP proxy API in NAP and put this class to there
	void proxyNapHttpResponse(PORT_IDENTIFIER portIdentifier,
			HTTP_METHOD httpMethod,	PACKET *reassembledPacket,
			PACKET_LENGTH reassembledPacketLength);
	/*!
	 *
	 */
	void publishData(ICN_ID icnId, string url, PACKET *packet,
			PACKET_LENGTH packetLength);
	/*!
	 * \brief
	 */
	void publishData(TRANSPORT_HEADER transport, ICN_ID icnId,
			PACKET *transportPayload, PACKET_LENGTH transportPayloadLength);
	/*!
	 * \brief
	 *
	 * \param icnId
	 *
	 */
	void publishDataiSub(ICN_ID icnId, ICN_ID iSubIcnId,
			TRANSPORT_KEY key,	PACKET *packet,
			PACKET_LENGTH packetLength,	boost::posix_time::ptime timestamp);
	/*!
	 *
	 */
	void readHeader(void *packet, TRANSPORT_HEADER &header);
	/*!
	 * \brief Publish packet under given ICN ID
	 *
	 * Prepare packet for unreliable publication of a data packet including
	 * fragmentation if required.
	 *
	 * \param icnId The ICN ID under which the packet is going to be published
	 * \param packet The packet which will be added as payload to the transport
	 * protocol
	 * \param packetLength The length of the transport protocol payload
	 */
	void sendPacket(ICN_ID icnId, PACKET *packet, PACKET_LENGTH packetLength);
private:
	NB_Blackadder *_nbBlackadder;	/*!< Non-blocking Blackadder instance*/
#ifdef DEBUG
	log4cxx::LoggerPtr _logger;		/*!< Pointer to log4cxx instance */
#endif
#ifdef TRACE
	Trace &_trace;					/*!< Reference to Trace class */
#endif
	Database &_db;					/*!< Reference to NAP database */
	/*!
	 * \brief
	 *
	 * \param transportPayloadLength
	 * \param payloadLength
	 */
	bool fragmentationRequired(PACKET_LENGTH transportPayloadLength,
			PACKET_LENGTH payloadLength);
};

#endif /* NAP_TRANSPORT_HH_ */
