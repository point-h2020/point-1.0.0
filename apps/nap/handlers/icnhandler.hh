/*
 * icnhandler.hh
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

#ifndef ICNHANDLER_HH_
#define ICNHANDLER_HH_

#include "../typedef.hh"
#include "../database.hh"
#include "../socket.hh"
#ifdef DEBUG
#include <log4cxx/logger.h>
#endif
#include <nb_blackadder.hpp>
#ifdef TRACE
#include "../trace.hh"
#endif
/*! \brief Handling Blackadder events
 *
 * This class is listening for Blackadder events and processes them as they
 * appear.
 */
class IcnHandler {
public:
	/*!
	 * \brief IcnHandler Constructor
	 *
	 * TBA
	 *
	 * \param logger Smart pointer to log4cxx class
	 * \param nbBlackadder Pointer to non-blocking Blackadder instance
	 * \param ev Pointer to the Blackadder event
	 * \param db Reference to the NAP database
	 * \param rawSocket Reference to the local socket to send ethernet frames
	 * towards the IP endpoint
	 * \param trace Reference to trace class
	 */
	IcnHandler(NB_Blackadder *nbBlackadder,
#ifdef DEBUG
			log4cxx::LoggerPtr logger,
#endif
#ifdef TRACE
			Trace &trace,
#endif
			Event *ev,
			Database &db,
			Socket &rawSocket)
		: _nbBlackadder(nbBlackadder),
#ifdef DEBUG
		  _logger(logger),
#endif
#ifdef TRACE
		  _trace(trace),
#endif
		  _ev(ev),
		  _db(db),
		  _rawSocket(rawSocket)
	{ }
	/*!
	 * \brief IcnHandler Deconstructor
	 */
	~IcnHandler();
	/*!
	 * \brief Functor
	 *
	 *
	 */
	void operator()();
private:
	NB_Blackadder *_nbBlackadder;	/*!< Pointer to Blackadder instance */
#ifdef DEBUG
	log4cxx::LoggerPtr _logger;		/*!< Pointer to log4cxx instance */
#endif
#ifdef TRACE
	Trace &_trace;					/*!< Reference to the Trace class */
#endif
	Event *_ev;						/*!< Pointer to the BA Event class */
	Database &_db;					/*!< Reference to the NAP database */
	Socket &_rawSocket;				/*!< Reference to the socket to send IP
										packets */
};

#endif /* ICNHANDLER_HH_ */
