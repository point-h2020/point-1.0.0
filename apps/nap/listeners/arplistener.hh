/*
 * arplistener.hh
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

#include "../typedef.hh"
#include "../database.hh"
#ifdef TRACE
#include "../trace.hh"
#endif
#include "../socket.hh"
#include <nb_blackadder.hpp>
#ifdef DEBUG
#include <log4cxx/logger.h>
#endif
#include <libnet.h>
#ifndef ARPLISTENER_HH_
#define ARPLISTENER_HH_

/*!
 * \brief ARP listener
 *
 * This class handles ARP request (ICMP) packets by generating ARP replies with
 * a randomly generated MAC address for the IP address in question. The
 * generated MAC address is stored in the NAP's database together with the
 * corresponding IP so that if the NAP receives an ARP request for this IP again
 * it can immediately reply with the previously generated MAC address.
 */
class ArpListener {
public:
	/*!
	 * \brief Constructor
	 *
	 * This constructor initialises the ArpHandler class with pointers and
	 * references to required classes and variables.
	 *
	 * \param logger Smart pointer to Log4cxx class
	 * \param device The device on which the ARP handler should send ARP
	 * messages
	 * \param nbBlackadder Pointer to Blackadder instance
	 * \param db Reference to NAP database
	 * \param packet Pointer to ARP request which must be handled
	 * \param packetCaptureTimeStamp The timestamp of when the ARP packet was
	 * received
	 * \param trace Reference to instantiated class Trace
	 * \param rawSocket Reference to instantiated class Socket
	 */
	ArpListener(NB_Blackadder *nbBlackadder,
#ifdef DEBUG
			log4cxx::LoggerPtr logger,
#endif
#ifdef TRACE
			Trace &trace,
#endif
			DEVICE *device,
			Database &db,
			PCAP_PACKET *packet,
			boost::posix_time::ptime packetCaptureTimeStamp,
			Socket &rawSocket)
	: _nbBlackadder(nbBlackadder),
#ifdef DEBUG
	  _logger(logger),
#endif
#ifdef TRACE
	  _trace(trace),
#endif
	  _device(device),
	  _db(db),
	  _packet(packet),
	  _packetCaptureTimeStamp(packetCaptureTimeStamp),
	  _rawSocket(rawSocket)
	{
		char error[LIBNET_ERRBUF_SIZE];
		libnet = libnet_init(LIBNET_LINK, _device, error);
#ifdef DEBUG
		if (libnet == NULL)
		{
			LOG4CXX_ERROR(_logger,"ARP socket could not be created on interface"
					<< _device);
		}
#endif
	}
	/*!
	 * \brief Deconstructor
	 */
	~ArpListener();
	/*!
	 * \brief Functor
	 *
	 * This functor is required when calling the ArpHandler as a boost::thread.
	 */
	void operator()();
private:
	NB_Blackadder *_nbBlackadder;/*!< Pointer to non-blocking Blackadder
	instance */
#ifdef DEBUG
	log4cxx::LoggerPtr _logger;	/*!< Smart pointer to log4cxx logging service*/
#endif
#ifdef TRACE
	Trace &_trace;				/*!< Trace class reference */
#endif
	DEVICE *_device;			/*!< The networking device name (e.g., eth2)
	on which the ARP handler is operating */
	Database &_db;				/*!< Reference to NAP database */
	PCAP_PACKET *_packet;		/*!< Pointer to the ARP request packet */
	boost::posix_time::ptime _packetCaptureTimeStamp; /*!< Timestamp when this
	ARP packet was captured */
	libnet_t *libnet;			/*!< Pointer to libnet socket to send packets */
	Socket &_rawSocket;			/*!< Socket class reference */
};

#endif /* ARPLISTENER_HH_ */
