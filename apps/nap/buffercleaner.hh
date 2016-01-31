/*
 * buffercleaner.hh
 *
 *  Created on: Nov 6, 2015
 *      Author: point
 */

#ifndef NAP_BUFFERCLEANER_HH_
#define NAP_BUFFERCLEANER_HH_
#include "database.hh"
class BufferCleaner {
public:
	BufferCleaner(Database &db)
	: _db(db)
	{ }
	~BufferCleaner();
	/*!
	 * \brief Functor
	 */
	void operator()();
private:
	Database &_db;
};

#endif /* NAP_BUFFERCLEANER_HH_ */
