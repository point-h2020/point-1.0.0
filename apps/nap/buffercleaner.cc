/*
 * buffercleaner.cc
 *
 *  Created on: Nov 6, 2015
 *      Author: point
 */

#include "buffercleaner.hh"

BufferCleaner::~BufferCleaner() {
	// TODO Auto-generated destructor stub
}

void BufferCleaner::operator ()()
{
	//ICN packet buffer
	_db.icnPacketBufferCleaner();
	//IP packet buffer
	_db.ipPacketBufferCleaner();
	//Assembly packet buffer
	_db.assemblyBufferCleaner();
	sleep(PACKET_TIMEOUT);
}
