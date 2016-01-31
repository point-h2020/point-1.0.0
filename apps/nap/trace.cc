/*
 * trace.cc
 *
 *  Created on: 2 Jul 2015
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

#include "trace.hh"
#include "enumerations.hh"
#include "helper.hh"
#include <netinet/ether.h>
Trace::~Trace() {
	traceFile.close();
}
void Trace::changeTraceFilePath(string filePath)
{
	ostringstream oss;
	traceFile.close();
	oss << filePath << "/napTrace.tsv";
	traceFile.open(oss.str().c_str(), ofstream::out | ofstream::trunc);
}
void Trace::closeTraceFile()
{
	traceFile.close();
}
void Trace::enableTracing()
{
	enabled = true;
}
string Trace::getMode(MODE mode)
{
	switch (mode)
	{
	case MODE_SENT:
		return "s";
		break;
	case MODE_RECEIVED:
		return "r";
		break;
	default:
		return "-";
	}
}
void Trace::writeToStream(string str)
{
	mutexTraceFile.lock();
	traceFile << str;
	mutexTraceFile.unlock();
}
void Trace::writeTrace(ICN_ID icnId, PACKET_LENGTH packetLength)
{
	if (!enabled)
		return;
	Helper helper;
	boost::posix_time::ptime currentTime;
	std::ostringstream oss;
	currentTime = boost::posix_time::microsec_clock::local_time();
	oss << currentTime.time_of_day() << "\t-\tr\tICN\t"
			<< helper.printIcnId(icnId) << "\t" << packetLength	<< endl;
	writeToStream(oss.str());
}
void Trace::writeTrace(MODE mode, ICN_ID icnId, PACKET_LENGTH packetLength,
			TRANSPORT_HEADER transport)
{
	if (!enabled)
		return;
	Helper helper;
	boost::posix_time::ptime currentTime;
	std::ostringstream oss;
	currentTime = boost::posix_time::microsec_clock::local_time();
	oss << currentTime.time_of_day() << "\t-\t" << getMode(mode) << "\tICN\t"
			<< helper.printIcnId(icnId) << "\t" << packetLength << "\t";
	switch (transport.state)
	{
	case TRANSPORT_STATE_START:
		oss << "START";
		break;
	case TRANSPORT_STATE_FRAGMENT:
		oss << "FRAGMENT";
		break;
	case TRANSPORT_STATE_FINISHED:
		oss << "FINISHED";
		break;
	case TRANSPORT_STATE_SINGLE_PACKET:
		oss << "SINGLE";
		break;
	default:
		oss << "UNKNOWN";
	}
	oss << "\t" << transport.sequence << "\t" << transport.key << endl;
	writeToStream(oss.str());
}
void Trace::writeTrace(ICN_ID icnId, PACKET_LENGTH packetLength,
			boost::posix_time::ptime packetReceivedTimestamp)
{
	if (!enabled)
		return;
	Helper helper;
	boost::posix_time::ptime currentTime;
	boost::posix_time::time_duration packetProcessingTime;//,duration;
	std::ostringstream oss;
	currentTime = boost::posix_time::microsec_clock::local_time();
	//duration = currentTime - napStartTime;
	packetProcessingTime = currentTime - packetReceivedTimestamp;
	//oss << duration.seconds() << "." << duration.fractional_seconds()
	oss << currentTime.time_of_day() << "\t"
			<< packetProcessingTime.total_microseconds() << "\ts\tICN\t"
			<< helper.printIcnId(icnId) << "\t" << packetLength << endl;
	writeToStream(oss.str());
}
void Trace::writeTrace(IP_ADDRESS srcIp, IP_ADDRESS dstIp, PORT port,
		PACKET_LENGTH packetLength)
{
	if (!enabled)
		return;
	Helper helper;
	boost::posix_time::ptime currentTime;
	//boost::posix_time::time_duration duration;
	std::ostringstream oss;
	currentTime = boost::posix_time::microsec_clock::local_time();
	//duration = currentTime - napStartTime;
	//oss << duration.seconds() << "." << duration.fractional_seconds()
	oss << currentTime.time_of_day() << "\t-\tr\tIP\t"
			<< helper.printIpAddress(srcIp) << "\t"
			<< helper.printIpAddress(dstIp) << "\t" << port	<< "\t"
			<< packetLength	<< endl;
	writeToStream(oss.str());
}
void Trace::writeTrace(MODE mode, IP_ADDRESS srcIp, IP_ADDRESS dstIp, PORT port,
		PACKET_LENGTH packetLength, int ipIdentification)
{
	if (!enabled)
		return;
	Helper helper;
	std::ostringstream oss;
	boost::posix_time::ptime currentTime =
			boost::posix_time::microsec_clock::local_time();
	oss << currentTime.time_of_day() << "\t-\t";
	switch (mode)
	{
	case MODE_SENT:
		oss << "s";
		break;
	case MODE_RECEIVED:
		oss << "r";
		break;
	default:
		oss << "-";
	}
	oss << "\tIP\t"
			<< helper.printIpAddress(srcIp) << "\t"
			<< helper.printIpAddress(dstIp) << "\t" << "-"	<< "\t"
			<< packetLength	<< "\tFRAG\t" << ipIdentification << endl;
	writeToStream(oss.str());
}
void Trace::writeTrace(IP_ADDRESS srcIp, IP_ADDRESS dstIp, string port,
		PACKET_LENGTH packetLength,
		boost::posix_time::ptime packetReceivedTimestamp)
{
	if (!enabled)
		return;
	Helper helper;
	boost::posix_time::ptime currentTime;
	//boost::posix_time::time_duration duration;
	boost::posix_time::time_duration packetProcessingTime;
	std::ostringstream oss;
	currentTime = boost::posix_time::microsec_clock::local_time();
	//duration = currentTime - napStartTime;
	packetProcessingTime = currentTime - packetReceivedTimestamp;
	//oss << duration.seconds() << "." << duration.fractional_seconds()
	oss << currentTime.time_of_day() << "\t"
			<< packetProcessingTime.total_microseconds() << "\ts\tIP\t"
			<< helper.printIpAddress(srcIp) << "\t"
			<< helper.printIpAddress(dstIp) << "\t";
	std::string::iterator end_pos = std::remove(port.begin(), port.end(), '0');
	port.erase(end_pos, port.end());
	oss << port << "\t"	<< packetLength	<< endl;
	writeToStream(oss.str());
}
void Trace::writeTrace(IP_ADDRESS srcIp, IP_ADDRESS dstIp, EUI48 srcMac)
{
	if (!enabled)
		return;
	Helper helper;
	boost::posix_time::ptime currentTime;
	//boost::posix_time::time_duration duration;
	std::ostringstream oss;
	currentTime = boost::posix_time::microsec_clock::local_time();
	//duration = currentTime - napStartTime;
	//oss << duration.seconds() << "." << duration.fractional_seconds()
	oss << currentTime.time_of_day() << "\t-\tr\tARP\tARPOP_REQUEST\t"
			<< helper.printIpAddress(srcIp) << "\t"
			<< helper.printIpAddress(dstIp) << "\t"
			<< helper.printEui48(srcMac) << "\tff:ff:ff:ff:ff:ff" << endl;
	writeToStream(oss.str());
}
void Trace::writeTrace(IP_ADDRESS srcIp, IP_ADDRESS dstIp, EUI48 srcMac,
		EUI48 dstMac, boost::posix_time::ptime packetReceivedTimestamp)
{
	if (!enabled)
		return;
	Helper helper;
	boost::posix_time::ptime currentTime;
	//boost::posix_time::time_duration duration;
	boost::posix_time::time_duration packetProcessingTime;
	std::ostringstream oss;
	currentTime = boost::posix_time::microsec_clock::local_time();
	//duration = currentTime - napStartTime;
	packetProcessingTime = currentTime - packetReceivedTimestamp;
	//oss << duration.seconds() << "." << duration.fractional_seconds()
	oss << currentTime.time_of_day() << "\t"
			<< packetProcessingTime.total_microseconds() << "\ts\tARP\t"
			<< "ARPOP_REPLY\t" << helper.printIpAddress(srcIp) << "\t"
			<< helper.printIpAddress(dstIp) << " \t"
			<< helper.printEui48(srcMac) << helper.printEui48(dstMac) << endl;
	writeToStream(oss.str());
}
void Trace::writeTrace(MODE mode, uint8_t arpMessageType,
		IP_ADDRESS ipAddressSender, IP_ADDRESS ipAddressTarget, EUI48 macSender,
		EUI48 macTarget)
{
	if (!enabled)
		return;
	Helper helper;
	boost::posix_time::ptime currentTime;
	boost::posix_time::time_duration duration;
	std::ostringstream oss;
	currentTime = boost::posix_time::microsec_clock::local_time();
	duration = currentTime - napStartTime;
	oss << currentTime.time_of_day();
	switch(arpMessageType)
	{
	case ARPOP_REQUEST:
	{
		oss << "\t-\t"<< getMode(mode) << "\tARP\tARPOP_REQUEST\t";
		break;
	}
	case ARPOP_REPLY:
	{
		oss << "\t-\t" << getMode(mode) << "\tARP\tARPOP_REPLY\t";
		break;
	}
	default:
		oss << "\t-\t" << getMode(mode) << "\tARP\tARPOP_UNKNOWN\t";
	}
	oss << helper.printIpAddress(ipAddressSender) << "\t"
			<< helper.printIpAddress(ipAddressTarget) << "\t"
			<< helper.printEui48(macSender) << " \t"
			<< helper.printEui48(macTarget) << endl;
	writeToStream(oss.str());
}
void Trace::writeTrace(uint16_t httpMethod, string fqdn, string resource,
				boost::posix_time::ptime packetReceivedTimestamp)
{
	if (!enabled)
		return;
	Helper helper;
	HASH_STR hashResource;
	std::ostringstream oss;
	oss << packetReceivedTimestamp.time_of_day() << "\t-\tr\t";
	if (httpMethod < 100)
	{
		oss << "HTTP\t" << httpMethod << "\t" << fqdn << resource << "\t"
		<< hashResource(resource);
	}
	else
	{
		oss << "HTTP\t" << httpMethod << "\t" << resource << "\t"
		<< hashResource(resource);
	}
	oss << endl;
	writeToStream(oss.str());
}
