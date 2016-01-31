/*
 * socket.hh
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
#ifndef SOCKET_HH_
#define SOCKET_HH_
#include "typedef.hh"
#ifdef DEBUG
#include <log4cxx/logger.h>
#endif
#include <libnet.h>
#include <nb_blackadder.hpp>
#include "database.hh"
#ifdef TRACE
#include "trace.hh"
#endif
/*!
 * \brief Send data (IP packet) in an Ethernet encapsulated packet
 *
 * This class allows to open a socket on a particular local network interface,
 * devise an Ethernet packet with IP data as its payload and send it out
 * eventually
 */
class Socket {
public:
	/*!
	 * Constructor
	 */
#ifdef DEBUG
#ifdef TRACE
	Socket(Database &db,
			log4cxx::LoggerPtr logger,
			Trace &trace
			)
	: _db(db),
	  _logger(logger),
	  _trace(trace)
#else
	Socket(Database &db,
			log4cxx::LoggerPtr logger
			)
	: _db(db),
	  _logger(logger)
#endif
#else
#ifdef TRACE
	Socket(Database &db,
			Trace &trace
			)
	: _db(db),
	  _trace(trace)
#else
	Socket(Database &db)
	: _db(db)
#endif
#endif
	{
		char error[LIBNET_ERRBUF_SIZE];
		// Note, this is just a work around to initialise the _libnet pointer.
		// It will be initialised to the proper interface in
		// Socket::createSocket()
		_libnet = libnet_init(LIBNET_LINK, NULL, error);
	}
	/*!
	 * Deconstructor
	 */
	~Socket();
	/*!
	 * \brief Create socket on particular device
	 *
	 * This function destroys the socket created in the constructor referenced
	 * by _libnet and creates a libnet_t socket on the interface provided in
	 * parameter 1
	 *
	 * \param device The device used to create the socket
	 *
	 * \return Boolean indicating whether or not the socket was created
	 * successfully
	 */
	bool createSocket(DEVICE *device);
	/*!
	 * \brief Sending an ARP request
	 *
	 * This function sends an ARP request asking all link-local neighbours for
	 * the MAC address of a particular IP endpoint.
	 *
	 * \param ipAddressTarget The IP endpoint for which the MAC address is
	 * required
	 */
	void sendArpRequest(IP_ADDRESS ipAddressTarget);
	/*!
	 * \brief Send an IP packet to a remote IP endpoint base on ICN ID
	 *
	 * This function takes an IP packet (header + payload), adds the required
	 * Ethernet frame including the determination of the correct MAC addresses
	 * and sends the final packet out.
	 *
	 * \param packet The IP packet which should be sent
	 * \param packetLength The length of the IP packet (header + payload)
	 * \param timeStamp
	 */
	void sendPacket(PACKET *packet, PACKET_LENGTH packetLength);
private:
	Database &_db;				/*!< Reference to database class */
#ifdef DEBUG
	log4cxx::LoggerPtr _logger;	/*!< Pointer to log4cxx instance */
#endif
#ifdef TRACE
	Trace &_trace;				/*!< Reference to trace class */
#endif
	libnet_t *_libnet;			/*!< Pointer to opened libnet socket */
	boost::mutex mutexLibnet;	/*!< make libnet_write sequential */
	/*!
	 * \brief
	 *
	 * \param macAddressSource
	 * \param macAddressDestination
	 * \param ipAddressSource
	 * \param ipAddressDestination
	 * \param packet
	 * \param totalPayloadSize
	 */
	void fragmentAndSendPacket(EUI48 macAddressSource,
			EUI48 macAddressDestination, IP_ADDRESS ipAddressSource,
			IP_ADDRESS ipAddressDestination, PACKET *payload,
			PACKET_LENGTH totalPayloadSize);
};

#endif /* SOCKET_HH_ */
