/*
 * iphandler.hh
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
#ifndef IPHANDLER_HH_
#define IPHANDLER_HH_
#ifdef DEBUG
#include <log4cxx/logger.h>
#endif
#include <nb_blackadder.hpp>
#include "../typedef.hh"
#include "../database.hh"
#ifdef TRACE
#include "../trace.hh"
#endif
/*!
 * \brief IpHandler class
 *
 * This class implements the IP-over-ICN handler which uses the class Database
 * to store state information about subscriptions, buffered packets and known IP
 * end-points.
 */
class IpHandler {
public:
	/*!
	 * \brief IpHandler Constructor
	 *
	 * \param logger Smart pointer to Log4cxx class
	 * \param nbBlackadder Pointer to non-blocking Blackadder instance
	 * \param srcIpAddress Source IP address of the IP packet to be handled
	 * \param dstIpAddress Destination IP address of the IP packet to be handled
	 * \param dstPort Port address of the IP endpoint
	 * \param packet The packet itself
	 * \param packetLength The length of the packet to be handled
	 * \param packetCaptureTimeStamp Timestamp of when the packet was captured
	 * \param db Reference to NAP database
	 * \param trace Reference to class Trace
	 */
	IpHandler(NB_Blackadder *nbBlackadder,
#ifdef DEBUG
			log4cxx::LoggerPtr logger,
#endif
#ifdef TRACE
			Trace &trace,
#endif
			IP_ADDRESS srcIpAddress,
			IP_ADDRESS dstIpAddress,
			PORT dstPort,
			PACKET *packet,
			PACKET_LENGTH packetLength,
			boost::posix_time::ptime packetCaptureTimeStamp,
			Database &db)
		: _nbBlackadder(nbBlackadder),
#ifdef DEBUG
		  _logger(logger),
#endif
#ifdef TRACE
		  _trace(trace),
#endif
		  _srcIpAddress(srcIpAddress),
		  _dstIpAddress(dstIpAddress),
		  _dstPort(dstPort),
		  _packet(packet),
		  _packetLength(packetLength),
		  _packetCaptureTimeStamp(packetCaptureTimeStamp),
		  _db(db)
	{ }
	/*!
	 * Deconstructor
	 */
	~IpHandler();
	/*!
	 * \brief Functor
	 *
	 * Functor to call this class from the outside (explicitly written for using boost::thread)
	 */
	void operator()();
private:
	NB_Blackadder *_nbBlackadder;	/*!< Non-blocking Blackadder instance*/
#ifdef DEBUG
	log4cxx::LoggerPtr _logger;		/*!< Pointer to log4cxx instance */
#endif
#ifdef TRACE
	Trace &_trace;					/*!< Reference to Trace class */
#endif
	IP_ADDRESS _srcIpAddress;		/*!< IP Address of the DST endpoint */
	IP_ADDRESS _dstIpAddress;		/*!< IP Address of the DST endpoint */
	PORT _dstPort;					/*!< Transport layer port of the DST
										endpoint */
	PACKET *_packet;			/*!< Packet pointer (IP header + payload) */
	PACKET_LENGTH _packetLength;	/*!< Length of the packet pointed to with
										_packet */
	boost::posix_time::ptime _packetCaptureTimeStamp; /*!< Timestamp of when this
										packet has been received */
	Database &_db;					/*!< Reference to NAP database */
};

#endif /* IPHANDLER_HH_ */
