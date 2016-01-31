/*
 * httphandler.hh
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
#ifndef HTTPHANDLER_HH_
#define HTTPHANDLER_HH_
#ifdef DEBUG
#include <log4cxx/logger.h>
#endif
#include <nb_blackadder.hpp>
#include "../database.hh"
#ifdef TRACE
#include "../trace.hh"
#endif
#include "../typedef.hh"
#include "../transport.hh"

class HttpHandler {
public:
	HttpHandler(NB_Blackadder *nbBlackadder,
#ifdef DEBUG
			log4cxx::LoggerPtr logger,
#endif
#ifdef TRACE
			Trace &trace,
#endif
			boost::posix_time::ptime packetCaptureTimeStamp,
			Database &db,
			PORT_IDENTIFIER portIdentifier,
			HTTP_METHOD httpMethod,
			string fqdn,
			string resource,
			TRANSPORT_KEY key,
			uint8_t *payload,
			PACKET_LENGTH payloadLength)
		: _nbBlackadder(nbBlackadder),
#ifdef DEBUG
		  _logger(logger),
#endif
#ifdef TRACE
		  _trace(trace),
#endif
		  _packetCaptureTimeStamp(packetCaptureTimeStamp),
		  _db(db),
		  _portIdentifier(portIdentifier),
		  _httpMethod(httpMethod),
		  _fqdn(fqdn),
		  _resource(resource),
		  _key(key),
		  _payload(payload),
		  _payloadLength(payloadLength)
	{ }
	~HttpHandler();
	void operator()();
private:
	NB_Blackadder *_nbBlackadder;	/*!< Non-blocking Blackadder instance*/
#ifdef DEBUG
	log4cxx::LoggerPtr _logger;		/*!< Pointer to log4cxx instance */
#endif
#ifdef TRACE
	Trace &_trace;					/*!< Reference to Trace class */
#endif
	boost::posix_time::ptime _packetCaptureTimeStamp; /*!< Timestamp of when this
										packet has been received */
	Database &_db;					/*!< Reference to NAP database */
	PORT_IDENTIFIER _portIdentifier;
	HTTP_METHOD _httpMethod;
	string _fqdn;
	string _resource;
	TRANSPORT_KEY _key;
	uint8_t *_payload;
	PACKET_LENGTH _payloadLength;
};

#endif /* HTTPHANDLER_HH_ */
