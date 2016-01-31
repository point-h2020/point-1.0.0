/*
 * trace.hh
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

#ifndef TRACE_HH_
#define TRACE_HH_
#include <boost/thread/mutex.hpp>
#include <iostream>
#include <fstream>
#include "typedef.hh"
/*!
 * \brief Trace class to write per packet NAP trace file
 *
 * This class allows to trace every single sent or received packet to be written
 * to a trace file using the following tsv format:
 * [1] NAP Timestamp [s]
 * [2] Packet processing time [μs]
 * [3] Operational mode
 * [4] Packet type
 *
 * --- if ARP ---
 * [5] ARP Type
 * [6] SRC IP
 * [7] DST IP
 * [8] SRC MAC Address
 * [9] DST MAC Address
 *
 * --- if IP ---
 * [5] SRC IP
 * [6] DST IP
 * [7] DST port number
 * [8] Layer 3 packet length (IP header + payload)
 * [9] Fragmentated packet
 *
 * --- if ICN ---
 * [5] ICN ID
 * [6] Packet length (ICN packet payload)
 * [7] Transport State
 * [8] Transport Sequence
 * [9] Transport Key
 * --- if HTTP ---
 * [5] Method number
 * 	---	Request
 * 	[6] URL
 * 	[7] Hashed resource
 * 	---	Response
 * 	[6] Resource
 * 	[7] Hashed resource
 *
 * IMPORTANT: While in operation the trace file will be only truncated. All
 * trace data is only written to internal output file stream in order to not
 * slow down the NAP by writing to disk. Once the NAP is requested to terminate
 * the deconstructor of the Trace class is called and the output file stream is
 * written to the trace file. In other words, a '$ tail -f napTrace.txt' while
 * the NAP is running won't show anything.
 */
class Trace {
public:
	/*!
	 * Constructor
	 */
	Trace()
	{
		enabled = false;
		filePath = "/tmp";
		traceFile.open("/tmp/napTrace.tsv", ofstream::out | ofstream::trunc);
		napStartTime = boost::posix_time::microsec_clock::local_time();
	}
	/*!
	 * Deconstructor
	 */
	~Trace();
	void closeTraceFile();
	/*!
	 * \brief Changing path to the tracestream file
	 *
	 * This function allows to set the directory under which the trace stream
	 * file is written to something other than /tmp
	 *
	 * \param filePath The file system path to where the trace stream file
	 * should be written to
	 */
	void changeTraceFilePath(string filePath);
	/*!
	 * \brief
	 */
	void enableTracing();
	/*!
	 *
	 */
	string getMode(MODE mode);
	/*!
	 * \brief Write string to trace file
	 *
	 * Function to write string to the trace file ensuring the stream is
	 * properly locked using mutex.
	 *
	 * \param oss The string which needs to be written to the trace file
	 */
	void writeToStream(string str);
	/*!
	 * \brief Write received ICN packet trace
	 *
	 * Write the trace entry for receiving an ICN packet in the ICN handler.
	 * Note, this function writes a "receive" operation only to the trace.
	 *
	 * \param icnId The ICN ID for which data has been received
	 * \param packetLength The length of the ICN payload
	 */
	void writeTrace(ICN_ID icnId, PACKET_LENGTH packetLength);
	/*!
	 * \brief
	 */
	void writeTrace(MODE mode, ICN_ID icnId, PACKET_LENGTH packetLength,
			TRANSPORT_HEADER transport);
	/*!
	 * \brief Write published ICN packet trace
	 *
	 * Write the trace entry for publishing an ICN packet. Note, this function
	 * writes a "send" operation to the trace.
	 *
	 * \param icnId The ICN under which data has been published
	 * \param packetLength The length of the ICN payload
	 * \param packetReceivedTimestamp The time when the packet was received
	 * by the NAP
	 */
	void writeTrace(ICN_ID icnId, PACKET_LENGTH packetLength,
			boost::posix_time::ptime packetReceivedTimestamp);
	/*!
	 * \brief Write received IP packet trace
	 *
	 * Write the trace entry an received IP packet from one of the IP
	 * endpoints. Note, this function writes a "received" operation only to the
	 * trace.
	 *
	 * \param srcIp The IP address of the sender
	 * \param dstIp The IP address of the destination (NAP)
	 * \param port The destination port number of the IP endpoint
	 * \param packetLength The length of the IP packet (header + payload)
	 */
	void writeTrace(IP_ADDRESS srcIp, IP_ADDRESS dstIp,	PORT port,
			PACKET_LENGTH packetLength);
	/*!
	 * \brief Write received IP packet trace
	 *
	 * Write the trace entry an received IP packet from one of the IP
	 * endpoints. Note, this function writes a "received" operation only to the
	 * trace.
	 *
	 * \param mode The type of operation (sent/received)
	 * \param srcIp The IP address of the sender
	 * \param dstIp The IP address of the destination (NAP)
	 * \param port The destination port number of the IP endpoint
	 * \param packetLength The length of the IP packet (header + payload)
	 * \param ipIdentificationId Idendification number of the IP packet in case
	 * it was fragmented
	 */
	void writeTrace(MODE mode, IP_ADDRESS srcIp, IP_ADDRESS dstIp, PORT port,
			PACKET_LENGTH packetLength, int ipIdentification);
	/*!
	 * \brief Write IP packet trace
	 *
	 * Write the trace entry for a sent IP packet to one of the IP
	 * endpoints. Note, this function writes a "sent" operation only to the
	 * trace.
	 *
	 * \param srcIp The IP address of the sender (NAP)
	 * \param dstIp The IP address of the destination
	 * \param port The destination port number of the IP endpoint
	 * \param packetLength The length of the IP packet (header + payload)
	 * \param packetReceivedTimestamp Time-stamp of when the ICN packet, in
	 * which this IP packet was delivered, was received
	 */
	void writeTrace(IP_ADDRESS srcIp, IP_ADDRESS dstIp, string port,
			PACKET_LENGTH packetLength,
			boost::posix_time::ptime packetReceivedTimestamp);
	/*!
	 * \brief Write received ARP packet trace
	 *
	 * Write the trace entry for a received ARP request packet from one of the
	 * IP endpoints. Note, this function writes a "received" operation only to
	 * the trace stream.
	 *
	 * \param srcIp The IP address of the sender of the ARP packet
	 * \param dstIp The IP address of the destination IP endpoint of this ARP
	 * packet
	 * \param srcMac The MAC address of the interface used by the source IP
	 * endpoint
	 */
	void writeTrace(IP_ADDRESS srcIp, IP_ADDRESS dstIp, EUI48 srcMac);
	/*!
	 * \brief Write ARPOP_REPLY packet trace
	 *
	 * Write the trace entry of the a sent ARP response to one of the NAP's IP
	 * endpoints. Note that this function writes a "sent" operation only to the
	 * trace stream.
	 *
	 * \param srcIp The IP address of the ARP sender (NAP)
	 * \param dstIp The IP address of the destination IP endpoint of this ARP
	 * response
	 * \param srcMac The MAC address of the interface used by the NAP to send
	 * the ARP response
	 * \param dstMac The MAC address of the destination interface used the
	 * destination IP endpoint when sending the ARP request
	 * \param packetReceivedTimestamp The timestamp when the corresponding ARP
	 * request was caputured
	 */
	void writeTrace(IP_ADDRESS srcIp, IP_ADDRESS dstIp, EUI48 srcMac,
			EUI48 dstMac, boost::posix_time::ptime packetReceivedTimestamp);
	/*!
	 * \brief Write ARP packet trace for arbitrary ARP msgs
	 *
	 * Write an ARP trace entry to the trace stream. This function is meant for
	 * ARP messages that just arrived (no processing duration will be written).
	 *
	 * \param mode The type of operation (sent/received)
	 * \param arpMessageType The ARP type, as defined in
	 * /usr/include/libnet/libnet-headers.h
	 * \param ipAddressSender The IP address of the ARP sender
	 * \param ipAddressTarget The IP address of the ARP target
	 * \param macSender The MAC address of the ARP sender
	 * \param macTarget The MAC address of the ARP target
	 */
	void writeTrace(MODE mode, uint8_t arpMessageType,
			IP_ADDRESS ipAddressSender, IP_ADDRESS ipAddressTarget,
			EUI48 macSender, EUI48 macTarget);
	/*!
	 * \brief tba
	 *
	 * tba
	 *
	 * \param httpMethod
	 */
	void writeTrace(uint16_t httpMethod, string fqdn, string uri,
				boost::posix_time::ptime packetReceivedTimestamp);
private:
	boost::mutex mutexTraceFile;	/*!< DB mutex to lock/unlock statistics
										file */
	boost::posix_time::ptime napStartTime; /*!< Timestamp when the NAP was
											started */
	std::ofstream traceFile;		/*!< output file stream */
	string filePath;				/*!< path to traceFile */
	bool enabled;	/*!< Indicating if trace was requested by user */
};

#endif /* TRACE_HH_ */
