/*
 * transport.cc
 *
 *  Created on: Oct 4, 2015
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

#include "helper.hh"
#include "transport.hh"

Transport::~Transport() {
	// TODO Auto-generated destructor stub
}

void Transport::assemblePacket(ICN_ID icnId, ICN_ID iSubIcnId,
		string nodeId, void *icnPacketPayload,
		PACKET_LENGTH icnPacketPayloadLength)
{
	TRANSPORT_HEADER header;
	Helper helper;
	PACKET *transportProtocolPayload;
	readHeader(icnPacketPayload, header);
	string mapKey = helper.toMapKey(icnId, nodeId, header.key);
	// Calculating transport protocol payload length
	PACKET_LENGTH transportProtocolPayloadLength =
			icnPacketPayloadLength - header.size;
	// Getting pointer to payload
	transportProtocolPayload = (PACKET *)icnPacketPayload + header.size;
	switch(header.state)
	{
	case TRANSPORT_STATE_START:
	{
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "First fragmented packet received for unqiue TP "
				<< "ID " << mapKey << " (Sequence: " << header.sequence
				<< ", Key: " << header.key << ", NodeID: " << nodeId << ")");
#endif
		_db.coincidentalMulticastAddNode(iSubIcnId, nodeId);
		_db.addPacketToAssemblyBuffer(header, icnId, nodeId,
				transportProtocolPayload, transportProtocolPayloadLength);
		break;
	}
	case TRANSPORT_STATE_FRAGMENT:
	{
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Fragmented packet received for unique TP ID "
				<< mapKey<< " (Sequence: "	<< header.sequence << ". Key: "
				<< header.key << ", NodeID: " << nodeId << ")");
#endif
		_db.addPacketToAssemblyBuffer(header, icnId, nodeId,
				transportProtocolPayload, transportProtocolPayloadLength);
		break;
	}
	case TRANSPORT_STATE_FINISHED:
	{
		PACKET *reassembledPacket;
		PACKET_LENGTH reassembledPacketLength;
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Final fragmented packet received for unique TP "
				<< "ID " << mapKey << " (Sequence: " << header.sequence
				<< ", Key: " << header.key << ", NodeID: " << nodeId << ")");
#endif
		_db.addPacketToAssemblyBuffer(header, icnId, nodeId,
				transportProtocolPayload, transportProtocolPayloadLength);
		// Get length of reassembled packet
		reassembledPacketLength =
				_db.getPacketLengthFromAssemblyBuffer(mapKey);
		if (reassembledPacketLength == transportProtocolPayloadLength)
		{
#ifdef DEBUG
			LOG4CXX_ERROR(_logger, "Transport protocol event type FINISHED "
					<< "received but a single packet transfer session");
#endif
			break;
		}
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Reassembled packet is "
				<< reassembledPacketLength << " bytes long");
#endif
		reassembledPacket = (PACKET *)malloc(reassembledPacketLength);
		if (_db.getPacketFromAssemblyBuffer(mapKey, reassembledPacket))
		{
			IP_ADDRESS ipAddress;
			_db.getFqdnIpAddressForIcnId(icnId, ipAddress);
			proxyNapHttpRequest(ipAddress, reassembledPacket,
					reassembledPacketLength);
		}
#ifdef DEBUG
		else
		{
			LOG4CXX_ERROR(_logger, "Could not reassemble fragmented packets for"
					<< " identifier "
					<< helper.toMapKey(icnId, nodeId, header.key));
		}
#endif
		break;
	}
	case TRANSPORT_STATE_SINGLE_PACKET:
	{
		IP_ADDRESS ipAddress;
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Single packet received for sequence "
				<< header.sequence << " and key " << header.key);
#endif
		_db.coincidentalMulticastAddNode(iSubIcnId, nodeId);
		_db.getFqdnIpAddressForIcnId(icnId, ipAddress);
		proxyNapHttpRequest(ipAddress, transportProtocolPayload,
				transportProtocolPayloadLength);
		break;
	}
#ifdef DEBUG
	default:
		LOG4CXX_ERROR(_logger, "Unknown transport protocol: State "
				<< header.state << " Sequence: " << header.sequence << ", Key "
				<< header.key << ", Size: "
				<< icnPacketPayloadLength - header.size);
#endif
	}
}

void Transport::assemblePacket(Socket &socket, ICN_ID icnId,
		void *icnPacketPayload, PACKET_LENGTH icnPacketPayloadLength)
{
	TRANSPORT_HEADER header;
	Helper helper;
	PACKET *transportProtocolPayload;
	readHeader(icnPacketPayload, header);
#ifdef TRACE
	_trace.writeTrace(MODE_RECEIVED, icnId, icnPacketPayloadLength, header);
#endif
	string mapKey = helper.toMapKey(icnId, header.key);
	// Calculating transport protocol payload length
	PACKET_LENGTH transportProtocolPayloadLength =
			icnPacketPayloadLength - header.size;
	// Getting pointer to payload
	transportProtocolPayload = (PACKET *)icnPacketPayload + header.size;
	switch(header.state)
	{
	// Fragmented piece
	case TRANSPORT_STATE_START:
	case TRANSPORT_STATE_FRAGMENT:
	case TRANSPORT_STATE_FINISHED:
	{
		PORT_IDENTIFIER portIdentifier;
		PACKET *reassembledPacket;
		PACKET_LENGTH reassembledPacketLength;
#ifdef DEBUG
		ostringstream oss;
		if (header.state == TRANSPORT_STATE_START)
			oss << "START";
		else if (header.state == TRANSPORT_STATE_FRAGMENT)
			oss << "FRAGMENT";
		else if (header.state == TRANSPORT_STATE_FINISHED)
			oss << "FINISHED";
		LOG4CXX_TRACE(_logger, "Packet fragment received for unique TP "
				<< "ID " << mapKey << " (State: " << oss.str() << ", Sequence: "
				<< header.sequence << ", Key: " << header.key << ")");
#endif
		_db.addPacketToAssemblyBuffer(header, icnId, transportProtocolPayload,
				transportProtocolPayloadLength);
		// check if the entire packet has been received
		if (!_db.packetReassemblyPossible(mapKey))
		{
			break;
		}
		// Get length of reassembled packet
		reassembledPacketLength =
				_db.getPacketLengthFromAssemblyBuffer(mapKey);
		reassembledPacket = (PACKET *)malloc(reassembledPacketLength);
		if (_db.getPacketFromAssemblyBuffer(mapKey, reassembledPacket))
		{
			switch (helper.getRootId(icnId))
			{
			case NAMESPACE_IP:
				socket.sendPacket(reassembledPacket, reassembledPacketLength);
				break;
			case NAMESPACE_HTTP:
				portIdentifier = _db.getPortIdentifier(icnId);
				// TODO get HTTP method from packet instead of hard coding it
				proxyNapHttpResponse(portIdentifier, HTTP_METHOD_RESPONSE_OK,
						reassembledPacket, reassembledPacketLength);
				break;
#ifdef DEBUG
			default:
				LOG4CXX_ERROR(_logger, "Unknown root scope "
						<< helper.getRootId(icnId) << ". Dropping reassembled "
						<< "packet");
#endif
			}
		}
#ifdef DEBUG
		else
		{
			LOG4CXX_ERROR(_logger, "Could not reassemble fragmented packets for"
					<< " identifier "
					<< helper.toMapKey(icnId, header.key));
		}
#endif
		break;
	}
	case TRANSPORT_STATE_SINGLE_PACKET:
	{
		PORT_IDENTIFIER portIdentifier;
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Single packet received for unique TP ID "
				<< mapKey << " (Sequence: " << header.sequence << ", Key: "
				<< header.key << ", Length " << transportProtocolPayloadLength
				<< ")");
#endif
		switch (helper.getRootId(icnId))
		{
		case NAMESPACE_IP:
			socket.sendPacket(transportProtocolPayload,
					transportProtocolPayloadLength);
			break;
		case NAMESPACE_HTTP:
			portIdentifier = _db.getPortIdentifier(icnId);
			// TODO get HTTP method from packet instead of hard coding it
			proxyNapHttpResponse(portIdentifier, HTTP_METHOD_RESPONSE_OK,
					transportProtocolPayload, transportProtocolPayloadLength);
			break;
#ifdef DEBUG
		default:
			LOG4CXX_ERROR(_logger, "Unknown root scope "
					<< helper.getRootId(icnId) << ". Dropping single "
					<< "packet");
#endif
		}
		break;
	}
#ifdef DEBUG
	default:
		LOG4CXX_ERROR(_logger, "Unknown transport protocol state. Sequence: "
				<< header.sequence << ", Key " << header.key << ", Size: "
				<< icnPacketPayloadLength - header.size);
#endif
	}
}

bool Transport::fragmentationRequired(PACKET_LENGTH transportPayloadLength,
			PACKET_LENGTH payloadLength)
{
	// Packet to be sent does not fit into single transport protocol payload
	if (payloadLength > transportPayloadLength)
		return true;
	return false;
}

void Transport::publishData(ICN_ID icnId, string url, PACKET *payload,
		PACKET_LENGTH payloadLength)
{
	Helper helper;
	TRANSPORT_STATE transportProtocolState;
	TRANSPORT_KEY key = rand();// get a random key. As this is mulicast
	// anyway it cannot be the TCP source port of the initial sender
	PACKET_LENGTH transportProtocolPayloadLength =
			_db.getIcnMtu() /* maximal ICN payload*/
			/*** ICN header ***/
			- (icnId.size() / 2) - 20 /* additional header fields */
			/*** Transport protocol header ***/
			- sizeof(TRANSPORT_STATE)
			- sizeof(TRANSPORT_SEQUENCE)
			- sizeof(TRANSPORT_KEY);
	list<NODE_ID> listOfNodeIds;
	if (!_db.coincidentalMulticastGetAllNodeIds(icnId, listOfNodeIds))
		return;
	_db.mutexSequenceNumbers.lock();
	// Fragmenting HTTP packet
	if (fragmentationRequired(transportProtocolPayloadLength, payloadLength))
	{
		size_t i = 0;
		while (i < payloadLength)
		{
#ifdef DEBUG
			ostringstream oss;
#endif
			// Last fragment reached
			if ((i + transportProtocolPayloadLength) > payloadLength)
			{
				transportProtocolState = TRANSPORT_STATE_FINISHED;
				transportProtocolPayloadLength = payloadLength - i;
#ifdef DEBUG
				oss << "Last packet fragment ";
#endif
			}
			else
			{
				if (i == 0)
				{
					transportProtocolState = TRANSPORT_STATE_START;
				}
				else
				{
					transportProtocolState = TRANSPORT_STATE_FRAGMENT;
				}
#ifdef DEBUG
				oss << "Fragment ";
#endif
			}
			PACKET_LENGTH transportProtocolLength =
					/* Transport protocol header */
					sizeof(TRANSPORT_STATE)
					+ sizeof(TRANSPORT_SEQUENCE)
					+ sizeof(TRANSPORT_KEY)
					/* Transport protocol payload */
					+ transportProtocolPayloadLength;
			PACKET *transportProtocolPacket =
					(PACKET *)malloc(transportProtocolLength);
			// Adding protocol state
			memcpy(transportProtocolPacket, &transportProtocolState,
					sizeof(TRANSPORT_STATE));
			// Adding sequence number
			memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE),
					&_db.sequenceNumber,
					sizeof(TRANSPORT_SEQUENCE));
			_db.sequenceNumber++;
			// Adding key
			memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE)
					+ sizeof(TRANSPORT_SEQUENCE), &key,
					sizeof(TRANSPORT_KEY));
			// Adding HTTP Broker header and HTTP packet
			memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE)
					+ sizeof(TRANSPORT_SEQUENCE)
					+ sizeof(TRANSPORT_KEY), payload + i,
					transportProtocolPayloadLength);
#ifdef DEBUG
			LOG4CXX_TRACE(_logger, oss.str() << "of length "
					<< transportProtocolLength << ", sequence "
					<< _db.sequenceNumber << " and key " << key
					<< " is getting published under scope "
					<< helper.printIcnId(icnId) << " via multicast (" << i
					<< "/" << payloadLength << " bytes sent)");
#endif
			/*_nbBlackadder->publish_data(hex_to_chararray(icnId),
						DOMAIN_LOCAL, NULL, 0, listOfNodeIds,
						transportProtocolPacket, transportProtocolLength);*/
			_nbBlackadder->publish_data(hex_to_chararray(icnId), DOMAIN_LOCAL,
					NULL, 0, transportProtocolPacket, transportProtocolLength);
			i += transportProtocolPayloadLength;
		}
	}
	// Single packet
	else
	{
		transportProtocolPayloadLength = payloadLength;
		PACKET_LENGTH transportProtocolPacketSize =
				/* Transport protocol header */
				sizeof(TRANSPORT_STATE)
				+ sizeof(TRANSPORT_SEQUENCE)
				+ sizeof(TRANSPORT_KEY)
				/* Transport protocol payload */
				+ transportProtocolPayloadLength;
		PACKET *transportProtocolPacket =
				(PACKET *)malloc(transportProtocolPacketSize);
		transportProtocolState = TRANSPORT_STATE_SINGLE_PACKET;
		// Adding protocol state
		memcpy(transportProtocolPacket, &transportProtocolState,
				sizeof(TRANSPORT_STATE));
		// Adding sequence number
		memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE),
				&_db.sequenceNumber,
				sizeof(TRANSPORT_SEQUENCE));
		_db.sequenceNumber++;
		// Adding key
		memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE)
				+ sizeof(TRANSPORT_SEQUENCE), &key,
				sizeof(TRANSPORT_KEY));
		// Adding actual HTTP fragment
		memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE)
				+ sizeof(TRANSPORT_SEQUENCE)
				+ sizeof(TRANSPORT_KEY), payload,
				transportProtocolPayloadLength);
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Single HTTP packet of length "
				<< transportProtocolPayloadLength << ", sequence "
				<< _db.sequenceNumber << " and key " << key
				<< " is getting published under scope "
				<< helper.printIcnId(icnId) << " via multicast");
#endif
		/*_nbBlackadder->publish_data(hex_to_chararray(icnId),
					DOMAIN_LOCAL, NULL, 0, listOfNodeIds,
					transportProtocolPacket, transportProtocolPayloadLength);*/
		_nbBlackadder->publish_data(hex_to_chararray(icnId), DOMAIN_LOCAL, NULL,
				0, transportProtocolPacket,	transportProtocolPayloadLength);
	}
	_db.mutexSequenceNumbers.unlock();
}

void Transport::publishData(TRANSPORT_HEADER transport, ICN_ID icnId,
		PACKET *transportPayload, PACKET_LENGTH transportPayloadLength)
{
	PACKET_LENGTH transportPacketLength =
			/* Transport protocol header */
			sizeof(TRANSPORT_STATE)
			+ sizeof(TRANSPORT_SEQUENCE)
			+ sizeof(TRANSPORT_KEY)
			/* Transport protocol payload */
			+ transportPayloadLength;
	PACKET *transportPacket =
			(PACKET *)malloc(transportPacketLength);
	// Adding protocol state
	memcpy(transportPacket, &transport.state,
			sizeof(TRANSPORT_STATE));
	// Adding sequence number
	memcpy(transportPacket + sizeof(TRANSPORT_STATE),
			&transport.sequence,
			sizeof(TRANSPORT_SEQUENCE));
	// Adding key
	memcpy(transportPacket + sizeof(TRANSPORT_STATE)
			+ sizeof(TRANSPORT_SEQUENCE), &transport.key,
			sizeof(TRANSPORT_KEY));
	// Adding HTTP Broker header and HTTP packet
	memcpy(transportPacket + sizeof(TRANSPORT_STATE)
			+ sizeof(TRANSPORT_SEQUENCE)
			+ sizeof(TRANSPORT_KEY), transportPayload,
			transportPayloadLength);
	_nbBlackadder->publish_data(hex_to_chararray(icnId),
				DOMAIN_LOCAL, NULL, 0,
				transportPacket, transportPacketLength);
#ifdef TRACE
	_trace.writeTrace(MODE_SENT, icnId, transportPacketLength, transport);
#endif
}

void Transport::publishDataiSub(ICN_ID icnId, ICN_ID iSubIcnId,
		TRANSPORT_KEY key, PACKET *payload,
		PACKET_LENGTH payloadLength, boost::posix_time::ptime timestamp)
{
	Helper helper;
	TRANSPORT_STATE transportProtocolState;
	// Calculate the maximal possible payload length which could go into a
	// single transport protocol payload field
	PACKET_LENGTH transportProtocolPayloadLength =
			_db.getIcnMtu() /* maximal possible(!) payload*/
			/*** ICN header ***/
			- (icnId.size() / 2) - 20 /* additional header fields */
			- (iSubIcnId.size() / 2) /* added to iSUB by BA */
			/*** Transport protocol header ***/
			- sizeof(TRANSPORT_STATE)
			- sizeof(TRANSPORT_SEQUENCE)
			- sizeof(TRANSPORT_KEY);
	_db.mutexSequenceNumbers.lock();
	// Fragmenting HTTP packet
	if (transportProtocolPayloadLength < payloadLength)
	{
		size_t i = 0;
		while (i < payloadLength)
		{
#ifdef DEBUG
			ostringstream oss;
#endif
			// Last fragment reached
			if ((i + transportProtocolPayloadLength) > payloadLength)
			{
				transportProtocolState = TRANSPORT_STATE_FINISHED;
				transportProtocolPayloadLength = payloadLength - i;
#ifdef DEBUG
				oss << "Last packet fragment ";
#endif
			}
			else
			{
				if (i == 0)
				{
					transportProtocolState = TRANSPORT_STATE_START;
				}
				else
				{
					transportProtocolState = TRANSPORT_STATE_FRAGMENT;
				}
#ifdef DEBUG
				oss << "Fragment ";
#endif
			}
			PACKET_LENGTH transportProtocolLength = sizeof(TRANSPORT_STATE)
					+ sizeof(TRANSPORT_SEQUENCE)
					+ sizeof(TRANSPORT_KEY)
					+ transportProtocolPayloadLength;
			PACKET *transportProtocolPacket =
					(PACKET *)malloc(transportProtocolLength);
			// Adding protocol state
			memcpy(transportProtocolPacket, &transportProtocolState,
					sizeof(TRANSPORT_STATE));
			// Adding sequence number
			memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE),
					&_db.sequenceNumber,
					sizeof(TRANSPORT_SEQUENCE));
			_db.sequenceNumber++;
			// Adding key
			memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE)
					+ sizeof(TRANSPORT_SEQUENCE), &key,
					sizeof(TRANSPORT_KEY));
			// Adding actual HTTP fragment
			memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE)
					+ sizeof(TRANSPORT_SEQUENCE)
					+ sizeof(TRANSPORT_KEY), payload + i,
					transportProtocolPayloadLength);
			/*_nbBlackadder->publish_data_isub(hex_to_chararray(icnId),
					DOMAIN_LOCAL, NULL, 0, iSubIcnId,
					transportProtocolPacket, transportProtocolLength);*/
#ifdef DEBUG
			LOG4CXX_TRACE(_logger, oss.str() << "of length "
					<< transportProtocolPayloadLength << ", sequence "
					<< _db.sequenceNumber << " and key " << key
					<< " is getting published under scope "
					<< helper.printIcnId(icnId) << " with iSub ICN ID "
					<< helper.printIcnId(iSubIcnId) << " (" << i << "/"
					<< payloadLength << " bytes sent)");
#endif
			i += transportProtocolPayloadLength;
#ifdef TRACE
			_trace.writeTrace(icnId, transportProtocolLength, timestamp);
#endif
		}
	}
	// No HTTP fragmentation required
	else
	{
		transportProtocolPayloadLength = payloadLength;
		PACKET_LENGTH transportProtocolPacketSize = sizeof(TRANSPORT_STATE)
				+ sizeof(TRANSPORT_SEQUENCE)
				+ sizeof(TRANSPORT_KEY)
				+ transportProtocolPayloadLength;
		PACKET *transportProtocolPacket =
				(PACKET *)malloc(transportProtocolPacketSize);
		transportProtocolState = TRANSPORT_STATE_SINGLE_PACKET;
		// Adding protocol state
		memcpy(transportProtocolPacket, &transportProtocolState,
				sizeof(TRANSPORT_STATE));
		// Adding sequence number
		memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE),
				&_db.sequenceNumber,
				sizeof(TRANSPORT_SEQUENCE));
		_db.sequenceNumber++;
		// Adding key
		memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE)
				+ sizeof(TRANSPORT_SEQUENCE), &key,
				sizeof(TRANSPORT_KEY));
		// Adding actual HTTP fragment
		memcpy(transportProtocolPacket + sizeof(TRANSPORT_STATE)
				+ sizeof(TRANSPORT_SEQUENCE)
				+ sizeof(TRANSPORT_KEY), payload,
				transportProtocolPayloadLength);
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Single HTTP packet of length "
				<< transportProtocolPayloadLength << ", sequence "
				<< _db.sequenceNumber << " and key " << key
				<< " is getting published under scope "
				<< helper.printIcnId(icnId));
#endif
		/*_nbBlackadder->publish_data_isub(hex_to_chararray(icnId),
				DOMAIN_LOCAL, NULL, 0, hex_to_chararray(iSubIcnId),
				transportProtocolPacket, transportProtocolPacketSize);*/
	}
	_db.mutexSequenceNumbers.unlock();
}

void Transport::readHeader(void *packet,
		TRANSPORT_HEADER &header)
{
	PACKET *packetPointer = (PACKET *)packet;
	// Read state
	memcpy(&header.state, packetPointer, sizeof(TRANSPORT_STATE));
	packetPointer += sizeof(TRANSPORT_STATE);
	// Read sequence number
	memcpy(&header.sequence, packetPointer, sizeof(TRANSPORT_SEQUENCE));
	packetPointer += sizeof(TRANSPORT_SEQUENCE);
	// Read key
	memcpy(&header.key, packetPointer, sizeof(TRANSPORT_KEY));
	packetPointer += sizeof(TRANSPORT_KEY);
}

void Transport::sendPacket(ICN_ID icnId, PACKET *packet,
		PACKET_LENGTH packetLength)
{
	Helper helper;
	TRANSPORT_HEADER transport;
	transport.key = rand();
	PACKET_LENGTH transportPayloadLength =
			_db.getIcnMtu() /* maximal ICN payload*/
			/*** ICN header ***/
			- icnId.size() - 20 /* additional header fields */
			/*** Transport protocol header ***/
			- sizeof(TRANSPORT_STATE)
			- sizeof(TRANSPORT_SEQUENCE)
			- sizeof(TRANSPORT_KEY);
	_db.mutexSequenceNumbers.lock();
	if (fragmentationRequired(transportPayloadLength, packetLength))
	{
		size_t bytesSent = 0;
		while (bytesSent < packetLength)
		{
#ifdef DEBUG
			ostringstream oss;
#endif
			// Last fragment reached
			if ((bytesSent + transportPayloadLength) > packetLength)
			{
				transport.state = TRANSPORT_STATE_FINISHED;
				transportPayloadLength = packetLength - bytesSent;
#ifdef DEBUG
				oss << "FINISHED";
#endif
			}
			else
			{
				if (bytesSent == 0)
				{
					transport.state = TRANSPORT_STATE_START;
#ifdef DEBUG
					oss << "START";
#endif
				}
				else
				{
					transport.state = TRANSPORT_STATE_FRAGMENT;
#ifdef DEBUG
					oss << "FRAGMENT";
#endif
				}
			}
			transport.sequence = _db.sequenceNumber++;
			publishData(transport, icnId, packet + bytesSent,
					transportPayloadLength);
#ifdef DEBUG

			LOG4CXX_TRACE(_logger, "Fragment of length "
					<< transportPayloadLength << ", State: " << oss.str()
					<< ", Sequence " << transport.sequence << " and Key "
					<< transport.key << " is getting published under scope "
					<< helper.printIcnId(icnId) << " (" << bytesSent
					<< "/" << packetLength << " bytes sent)");
#endif
			bytesSent += transportPayloadLength;
		}
	}
	// Single packet
	else
	{
		transport.state = TRANSPORT_STATE_SINGLE_PACKET;
		transport.sequence = _db.sequenceNumber++;
		publishData(transport, icnId, packet, packetLength);
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Single packet of length "
				<< packetLength << ", Sequence "
				<< transport.sequence << " and key " << transport.key
				<< " is getting published under scope "
				<< helper.printIcnId(icnId));
#endif
	}
	_db.mutexSequenceNumbers.unlock();
}

void Transport::proxyNapHttpRequest(IP_ADDRESS ipAddress,
		PACKET *reassembledPacket, PACKET_LENGTH reassembledPacketLength)
{
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov[4];
	struct msghdr msg;
	int fd, ret;
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0)
	{
#ifdef DEBUG
		LOG4CXX_FATAL(_logger, "Could not create socket");
#endif
		return;
	}
	memset(&msg, 0, sizeof(msg));
	memset(&src_addr, 0, sizeof(src_addr));
	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&iov, 0, sizeof(iov));
	// SRC Address
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = PID_NAP_SENDER_HTTP_REQUEST;  /* self pid */
	src_addr.nl_groups = 0;  /* not in mcast groups */
	src_addr.nl_pad = 0;
	ret = bind(fd, (struct sockaddr*) &src_addr, sizeof(src_addr));
	if (ret < 0)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Could not bind to socket with PID "
				<< src_addr.nl_pid);
#endif
		return;
	}
	// DST address
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = PID_PROXY_NAP_LISTENER;
	dest_addr.nl_groups = 0; /* unicast */
	dest_addr.nl_pad = 0;
	/* Fill in the netlink message payload */
	nlh=(struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_MESSAGE_PAYLOAD));
	/* Fill the netlink message header */
	nlh->nlmsg_len = sizeof(struct nlmsghdr);
	nlh->nlmsg_pid = PID_NAP_SENDER_HTTP_REQUEST; //getpid()
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = PROXY_NAP_HTTP_REQUEST;
	nlh->nlmsg_seq = 0;
	iov[0].iov_base = nlh;
	iov[0].iov_len = sizeof(*nlh);
	// IP Address
	iov[1].iov_base = &ipAddress;
	iov[1].iov_len = sizeof(IP_ADDRESS);
	nlh->nlmsg_len += iov[1].iov_len;
	// Packet length (Note, this includes FQDN, Resource, HTTP Request)
	iov[2].iov_base = &reassembledPacketLength;
	iov[2].iov_len = sizeof(PACKET_LENGTH);
	nlh->nlmsg_len += iov[2].iov_len;
	//printf("Reassembled packet length %d\n", *(PACKET_LENGTH *)iov[2].iov_base);
	// Packet
	iov[3].iov_base = (void *)reassembledPacket;
	iov[3].iov_len = reassembledPacketLength;
	nlh->nlmsg_len += iov[3].iov_len;
	// Creating message
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 4;
	ret = sendmsg(fd, &msg, MSG_TRUNC);
	if (ret < 0)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Sending message to PID " << dest_addr.nl_pid
				<< " failed with error code: " << ret);
#endif
		close(fd);
		return;
	}
#ifdef DEBUG
	LOG4CXX_TRACE(_logger, "PROXY_NAP_HTTP_REQUEST packet of length "
			<< nlh->nlmsg_len << " sent to proxy");
#endif
	close(fd);
}

void Transport::proxyNapHttpResponse(
		PORT_IDENTIFIER portIdentifier, HTTP_METHOD httpMethod,
		PACKET *reassembledPacket, PACKET_LENGTH reassembledPacketLength)
{
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov[4];
	struct msghdr msg;
	int fd, ret;
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0)
	{
#ifdef DEBUG
		LOG4CXX_FATAL(_logger, "Could not create socket");
#endif
		return;
	}
	// Setting everything to 0
	memset(&msg, 0, sizeof(msg));
	memset(&src_addr, 0, sizeof(src_addr));
	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&iov, 0, sizeof(iov));
	// Now add content
	// SRC Address
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = PID_NAP_SENDER_HTTP_RESPONSE;  /* self pid */
	src_addr.nl_groups = 0;  /* not in mcast groups */
	src_addr.nl_pad = 0;
	ret = bind(fd, (struct sockaddr*) &src_addr, sizeof(src_addr));
	if (ret < 0)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Could not bind to socket with PID "
				<< src_addr.nl_pid);
#endif
		return;
	}
	// DST address
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = portIdentifier;// stored when received the HTTP Request
	dest_addr.nl_groups = 0; /* unicast */
	dest_addr.nl_pad = 0;
	/* Fill in the netlink message payload */
	nlh=(struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_MESSAGE_PAYLOAD));
	/* Fill the netlink message header */
	nlh->nlmsg_len = sizeof(struct nlmsghdr);
	nlh->nlmsg_pid = PID_NAP_SENDER_HTTP_RESPONSE;//getpid()
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = PROXY_NAP_HTTP_RESPONSE;
	nlh->nlmsg_seq = rand();//No one reads this field. Just make it unique
	iov[0].iov_base = nlh;
	iov[0].iov_len = sizeof(*nlh);
	// HTTP method
	iov[1].iov_base = &httpMethod;
	iov[1].iov_len = sizeof(HTTP_METHOD);
	nlh->nlmsg_len += iov[1].iov_len;
	// Packet length
	iov[2].iov_base = &reassembledPacketLength;
	iov[2].iov_len = sizeof(PACKET_LENGTH);
	nlh->nlmsg_len += iov[2].iov_len;
	// Packet
	iov[3].iov_base = (void *)reassembledPacket;
	iov[3].iov_len = reassembledPacketLength;
	nlh->nlmsg_len += iov[3].iov_len;
	// Creating message
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 4;
	ret = sendmsg(fd, &msg, MSG_TRUNC);
	if (ret < 0)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "PROXY_NAP_HTTP_RESPONSE packet of length "
					<< nlh->nlmsg_len << " sent to proxy failed (PID "
					<< portIdentifier <<"): " << ret);
#endif
		close(fd);
		return;
	}
#ifdef DEBUG
	LOG4CXX_TRACE(_logger, "PROXY_NAP_FORWARD_HTTP_RESPONSE packet of length "
			<< nlh->nlmsg_len << " sent to proxy (PID "<< portIdentifier
			<<", Sequence: " << nlh->nlmsg_seq << ")");
#endif
	close(fd);
}
