/*
 * demux.hh
 *
 *  Created on: 19 Apr 2015
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
#ifdef DEBUG
#include <log4cxx/logger.h>
#endif
#include "typedef.hh"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <nb_blackadder.hpp>
#include "database.hh"
#ifdef TRACE
#include "trace.hh"
#endif
#include "socket.hh"
#ifndef DEMUX_HH_
#define DEMUX_HH_

/*!
 * \brief Demux
 *
 * Class for listening on socket for any incoming packet and to demultiplex them based on Ethernet type, IP protocol type and transport protocol.
 */
class Demux {
public:
	/*!
	 * \brief Demux Constructor
	 *
	 * n/a
	 *
	 * \param logger Smart pointer to Log4cxx class
	 * \param nbBlackadder Pointer to non-blocking Blackadder instance
	 * \param device The networking device on which the IpDemux should listen
	 * for incoming packets
	 * \param db Reference to NAP database
	 * \param trace Reference to trace class
	 * \param rawSocket Reference to the class Socket
	 */
	Demux(NB_Blackadder *nbBlackadder,
#ifdef DEBUG
			log4cxx::LoggerPtr logger,
#endif
#ifdef TRACE
			Trace &trace,
#endif
			DEVICE *device,
			Database &db,
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
		  _rawSocket(rawSocket)
	{ }
	/*!
	 * \brief IpDemux Deconstructor
	 */
	~Demux();
	/*!
	 * \brief Change scheduler parameters for this demux thread
	 *
	 * \param demuxThread Reference to the demux thread
	 */
	void changeSchedulerParameters(boost::thread &demuxThread);
	/*!
	 * \brief Starting the IP demuxer using ipDemux() in main
	 *
	 * Boost functor to call this class as a dedicated thread
	 */
	void operator()();
	/*!
	 * \brief Reading the header information of an incoming packet
	 *
	 * TODO
	 *
	 * \param args TODO
	 * \param header TODO
	 * \param packet TODO
	 */
	/*void processPacket(u_char *args, const struct pcap_pkthdr *header,
			    const u_char *packet);*/
	void processPacket(const struct pcap_pkthdr *header, const u_char *packet);
	void shutdown();
private:
	NB_Blackadder *_nbBlackadder;	/*!< Non-blocking Blackadder instance */
#ifdef DEBUG
	log4cxx::LoggerPtr _logger;		/*!< Pointer to log4cxx instance */
#endif
#ifdef TRACE
	Trace &_trace;					/*!< Reference to class Trace */
#endif
	DEVICE *_device;				/*!< Local interface on which this demux is operating on */
	Database &_db;					/*!< Reference to NAP database */
	Socket &_rawSocket;				/*!< Reference to class Socket */
	PCAP_HANDLER *_pcapHandler = NULL;
};

#endif /* DEMUX_HH_ */
