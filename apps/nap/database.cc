/*
 * database.cc
 *
 *  Created on: 18 May 2015
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

#include "database.hh"
#include "helper.hh"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
Database::~Database() { }
void Database::addIcnId(ICN_ID icnId)
{
	Helper helper;
	if (findIcnId(icnId))
		return;
	switch (helper.getRootId(icnId))
	{
	case NAMESPACE_IP:
	{
		ROUTING_PREFIX routingPrefix;
		string ipAddrString = helper.getScopeId(icnId, SCOPE_LEVEL_IP_IPADDRESS);
		string portString = helper.getScopeId(icnId, SCOPE_LEVEL_IP_PORT);
		IP_ADDRESS ipAddress = atoll(ipAddrString.c_str());
		PORT port = atoi(portString.c_str());
		if (!getRoutingPrefix(ipAddress, routingPrefix))
			return;
		addIcnId(icnId, ipAddress, port, false);
		break;
	}
	case NAMESPACE_HTTP:
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Plain ICN ID insertion not supported anymore");
#endif
		//addIcnId(icnId, "");
		break;
	}
#ifdef DEBUG
	default:
		LOG4CXX_ERROR(_logger, "Unknown namespace. ICN ID"
				<< helper.printIcnId(icnId) << " was not added to DB");
#endif
	}
}
void Database::addIcnId(ICN_ID icnId, IP_ADDRESS ipAddress, PORT port,
		bool localInterface)
{
	Helper helper;
	ICN_ID_DESCR_STRUCT descr;
	ostringstream oss;
	ROUTING_PREFIX routingPrefix;
	if (findIcnId(icnId))
		return;
	if (!getRoutingPrefix(ipAddress, routingPrefix))
		return;
	descr.routingPrefix = routingPrefix;
	descr.ipAddress = ipAddress;
	descr.port = port;
	descr.fwPolicy = false;
	descr.localInterface = localInterface;
	descr.scopesPublished = false;
	mutexIpIcnIdDescription.lock();
	icnIdDescr.insert(pair<ICN_ID,ICN_ID_DESCR_STRUCT>(icnId, descr));
	mutexIpIcnIdDescription.unlock();
#ifdef DEBUG
	if (localInterface)
	{
		LOG4CXX_DEBUG(_logger, "New ICN ID (local interface) "
				<< helper.printIcnId(icnId) << " (Prefix: "
				<< helper.printRoutingPrefix(routingPrefix) << ", IP: "
				<< helper.printIpAddress(ipAddress)	<< ", Port: " << port
				<< ") has been added to DB");
	}
	else
	{
		LOG4CXX_DEBUG(_logger, "New ICN ID "
				<< helper.printIcnId(icnId) << " (Prefix: "
				<< helper.printRoutingPrefix(routingPrefix) << ", IP: "
				<< helper.printIpAddress(ipAddress)	<< ", Port: " << port
				<< ") has been added to DB");
	}
#endif
}
void Database::addIcnId(ICN_ID icnId, uint8_t type)
{
	Helper helper;
	ICN_ID_DESCRIPTION_HTTP description;
	if (findIcnId(icnId))
		return;
#ifdef DEBUG
	switch (type)
	{
	case TYPE_FQDN:
		LOG4CXX_DEBUG(_logger, "New ICN ID " << helper.printIcnId(icnId)
				<< " was added to database (Type FQDN)");
		break;
	case TYPE_URL:
		LOG4CXX_DEBUG(_logger, "New ICN ID " << helper.printIcnId(icnId)
				<< " was added to database (Type URL)");
		break;
	}
#endif
	description.scopesPublished = false;
	description.forwardingPolicy = false;
	description.httpMethod = 0x0;
	mutexHttpIcnIdDescription.lock();
	icnIdDescriptionHttp.insert(
			pair<ICN_ID, ICN_ID_DESCRIPTION_HTTP>(icnId, description));
	mutexHttpIcnIdDescription.unlock();
}
void Database::addIcnId(ICN_ID icnId, string fqdn, IP_ADDRESS ipAddress)
{
	Helper helper;
	ICN_ID_DESCRIPTION_HTTP description;
	HASH_STR hashFqdn;
	if (findIcnId(icnId))
		return;
	description.scopesPublished = false;
	description.forwardingPolicy = false;
	description.fqdn = fqdn;
	description.hashedFqdn = hashFqdn(fqdn);
	description.ipAddress = ipAddress;
	mutexHttpIcnIdDescription.lock();
	icnIdDescriptionHttp.insert(
			pair<ICN_ID, ICN_ID_DESCRIPTION_HTTP>(icnId, description));
	mutexHttpIcnIdDescription.unlock();
#ifdef DEBUG
	LOG4CXX_DEBUG(_logger, "New ICN ID " << helper.printIcnId(icnId)
			<< " was added to database (FQDN: " << fqdn << ", "
			<< helper.printIpAddress(ipAddress) << ")");
#endif
}
void Database::addIcnId(ICN_ID icnId, string fqdn, string resource)
{
	Helper helper;
	ICN_ID_DESCRIPTION_HTTP description;
	HASH_STR hashStr;
	if (findIcnId(icnId))
		return;
	description.scopesPublished = false;
	description.forwardingPolicy = false;
	description.fqdn = fqdn;
	description.hashedFqdn = hashStr(fqdn);
	description.resource = resource;
	description.hashedResource = hashStr(resource);
#ifdef DEBUG
	LOG4CXX_DEBUG(_logger, "New ICN ID " << helper.printIcnId(icnId)
			<< " is being added to database (FQDN: '"
			<< fqdn << "', Resource: '" << resource << "')");
#endif
	mutexHttpIcnIdDescription.lock();
	icnIdDescriptionHttp.insert(
			pair<ICN_ID, ICN_ID_DESCRIPTION_HTTP>(icnId, description));
	mutexHttpIcnIdDescription.unlock();
}
void Database::addIcnId(ICN_ID icnId, string fqdn, string resource,
		PORT_IDENTIFIER portIdentifier)
{
	Helper helper;
	string url;
	ICN_ID_DESCRIPTION_HTTP description;
	HASH_STR hashStr;
	if (findIcnId(icnId))
		return;
	description.scopesPublished = false;
	description.forwardingPolicy = false;
	description.fqdn = fqdn;
	description.hashedFqdn = hashStr(fqdn);
	description.resource = resource;
	description.hashedResource = hashStr(resource);
	description.portIdentifier = portIdentifier;
	url = fqdn;
	url.append(resource);
#ifdef DEBUG
	LOG4CXX_DEBUG(_logger, "New ICN ID " << helper.printIcnId(icnId)
			<< " is being added to database (URL: '" << url << "', PID "
			<< portIdentifier << ")");
#endif
	mutexHttpIcnIdDescription.lock();
	icnIdDescriptionHttp.insert(
			pair<ICN_ID, ICN_ID_DESCRIPTION_HTTP>(icnId, description));
	mutexHttpIcnIdDescription.unlock();
}
void Database::addIpEndpoint(IP_ADDRESS ipAddress)
{
	IP_ADDRESS_VECTOR_IT it;
	Helper helper;
	mutexNapIpEndpoints.lock();
	for (it = napIpEndpoints.begin(); it != napIpEndpoints.end(); it++)
	{
		if ((*it) == ipAddress)
		{
			mutexNapIpEndpoints.unlock();
			return;
		}
	}
	napIpEndpoints.push_back(ipAddress);
	mutexNapIpEndpoints.unlock();
#ifdef DEBUG
	LOG4CXX_DEBUG(_logger, "New NAP IP endpoint "
			<< helper.printIpAddress(ipAddress) << " was added to DB");
#endif
}
void Database::addIpEui48Pair(IP_ADDRESS ipAddress, EUI48 eui48)
{
	Helper helper;
	IP_EUI48_MAP::iterator it;
	ostringstream oss;
	mutexArpTable.lock();
	it = arpTable.find(ipAddress);
	if (it == arpTable.end())
	{
		// First bring the eui48 address into the right format, i.e.: 0:4:1d
		if (eui48.find(":") == string::npos)
		{
			for (int i = 0; i <= 5; i++)
			{
				if (eui48.compare(2*i,1,"0") == 0)
				{
					oss << eui48[2*i+1];
				}
				else
				{
					oss << eui48[2*i] << eui48[2*i+1];
				}
				if (i != 5)
					oss << ":";
			}
		}
		else
			oss << eui48;
		arpTable.insert(pair<IP_ADDRESS, EUI48>(ipAddress, oss.str()));
#ifdef DEBUG
		LOG4CXX_DEBUG(_logger, "Added new IP-MAC entry: "
				<< helper.printIpAddress(ipAddress) << " <> " << oss.str());
#endif
	}
	mutexArpTable.unlock();
}

void Database::addPacketToIcnBuffer(ICN_ID icnId, PCAP_PACKET *packet,
		PACKET_LENGTH packetLength,	boost::posix_time::ptime timeStamp)
{
	addPacketToIcnBuffer(icnId, 0, packet, packetLength, timeStamp);
}

void Database::addPacketToIcnBuffer(ICN_ID icnId, TRANSPORT_KEY key,
		PCAP_PACKET *packet, PACKET_LENGTH packetLength,
		boost::posix_time::ptime timeStamp)
{
	PACKET_BUFFER_STRUCT descr;
	Helper helper;
	descr.packetDescription.packet =
			reinterpret_cast<PACKET *>(malloc(packetLength+1));
	memcpy(descr.packetDescription.packet, packet, packetLength);
	descr.key = key;
	descr.packetDescription.packetLength = packetLength;
	descr.packetDescription.timeStamp = timeStamp;
	mutexIcnPacketBuffer.lock();
	icnPacketBuffer.push_back(pair<ICN_ID, PACKET_BUFFER_STRUCT>(icnId, descr));
	mutexIcnPacketBuffer.unlock();
#ifdef DEBUG
	LOG4CXX_TRACE(_logger,"ICN packet of length "
			<< descr.packetDescription.packetLength << " for ICN ID "
			<< helper.printIcnId(icnId)	<< " has been added to ICN packet buffer. "
			<< icnPacketBuffer.size() << " packets currently in buffer");
#endif
}

void Database::addPacketToIpBuffer(IP_ADDRESS ipAddress, PCAP_PACKET *packet,
		PACKET_LENGTH packetLength)
{
	PACKET_BUFFER_STRUCT descr;
	Helper helper;
	descr.packetDescription.packet = reinterpret_cast<PACKET *>(malloc(packetLength));
	memcpy(descr.packetDescription.packet, packet, packetLength);
	descr.packetDescription.packetLength = packetLength;
	descr.packetDescription.timeStamp =
			boost::posix_time::microsec_clock::local_time();
	mutexIpPacketBuffer.lock();
	ipPacketBuffer.push_back(
			pair< IP_ADDRESS, PACKET_BUFFER_STRUCT >(ipAddress,	descr));
	mutexIpPacketBuffer.unlock();
#ifdef DEBUG
	LOG4CXX_TRACE(_logger,"IP packet of length "
			<< descr.packetDescription.packetLength << " for IP "
			<< helper.printIpAddress(ipAddress)
			<< " has been added to IP packet buffer. " << ipPacketBuffer.size()
			<< " packets currently in IP buffer");
#endif
}

void Database::addPacketToAssemblyBuffer(TRANSPORT_HEADER header,
			ICN_ID icnId, PACKET *transportProtocolPayload,
			PACKET_LENGTH transportProtocolPayloadLength)
{
	addPacketToAssemblyBuffer(header, icnId, "00000000",
			transportProtocolPayload, transportProtocolPayloadLength);
}

void Database::addPacketToAssemblyBuffer(TRANSPORT_HEADER header,
			ICN_ID icnId, string nodeId, PACKET *transportProtocolPayload,
			PACKET_LENGTH transportProtocolPayloadLength)
{
	ASSEMBLY_BUFFER_MAP::iterator assemblyBufferIt;
	FRAGMENTED_PACKET_DESCRIPTION fragmentedPacket;
	string mapKey;
	Helper helper;
	mapKey = helper.toMapKey(icnId, nodeId, header.key);
	// Copy packet in packet pair
	fragmentedPacket.packetDescription.packet = (PACKET *)malloc(transportProtocolPayloadLength);
	memcpy(fragmentedPacket.packetDescription.packet,
			(PACKET *)transportProtocolPayload, transportProtocolPayloadLength);
	fragmentedPacket.packetDescription.packetLength =
			transportProtocolPayloadLength;
	fragmentedPacket.packetDescription.timeStamp =
			boost::posix_time::microsec_clock::local_time();
	fragmentedPacket.transportState = header.state;
	// Now find the map key and add packet
	mutexAssemblyBuffer.lock();
	assemblyBufferIt = assemblyBuffer.find(mapKey);
	// Another fragmented piece of this packet already exists
	if (assemblyBufferIt != assemblyBuffer.end())
	{
#ifdef DEBUG
		if (header.state == TRANSPORT_STATE_START)
		{
			LOG4CXX_DEBUG(_logger, "First fragmented packet for map key "
					<< mapKey << " received out of order. Continue anyway")
		}
#endif
		(*assemblyBufferIt).second.insert(pair <TRANSPORT_SEQUENCE,
				FRAGMENTED_PACKET_DESCRIPTION>(header.sequence, fragmentedPacket));
	}
	// First fragment received
	else
	{
		ASSEMBLY_PACKET_MAP assemblyPacketMap;
#ifdef DEBUG
		if (header.state == TRANSPORT_STATE_FINISHED ||
				header.state == TRANSPORT_STATE_FRAGMENT)
		{
			LOG4CXX_DEBUG(_logger, "Fragmented packet for map key "
					<< mapKey << " received out of order. Continue anyway");
		}
#endif
		// Creating new map for packet fragments
		assemblyPacketMap.insert(
				pair<TRANSPORT_SEQUENCE, FRAGMENTED_PACKET_DESCRIPTION>
					(header.sequence, fragmentedPacket));
		// Adding this new map to assembly packet buffer
		assemblyBuffer.insert(
				pair <ASSEMBLY_BUFFER_UNIQUE_KEY, ASSEMBLY_PACKET_MAP>
				(mapKey, assemblyPacketMap));
	}
	mutexAssemblyBuffer.unlock();
}
void Database::addRoutingPrefix(ROUTING_PREFIX routingPrefix)
{
	HASH_STR hashStr;
	stringstream oss;
	Helper helper;
	oss << dec << routingPrefix.networkAddress;
	if (oss.str().length() > ID_LEN)
	{
		routingPrefix.hashedPrefix = hashStr(oss.str());
	}
	else
	{
		routingPrefix.hashedPrefix = routingPrefix.networkAddress;
	}
	routingPrefix.appliedMask = routingPrefix.networkAddress & routingPrefix.netmask;
	mutexRoutingPrefixes.lock();
	routingPrefixes.push_back(routingPrefix);
#ifdef DEBUG
	LOG4CXX_DEBUG(_logger, "New routing prefix "
			<< helper.printRoutingPrefix(routingPrefix) << " was added to DB. "
			<< routingPrefixes.size() << " routing prefix entries in DB");
#endif
	mutexRoutingPrefixes.unlock();
}
void Database::assemblyBufferCleaner()
{
	ASSEMBLY_BUFFER_MAP::iterator assemblyBufferIt;
	mutexAssemblyBuffer.lock();
	assemblyBufferIt = assemblyBuffer.begin();
	while (assemblyBufferIt != assemblyBuffer.end())
	{
		ASSEMBLY_PACKET_MAP::iterator assemblyPacketIt;
		boost::posix_time::time_duration duration;
		boost::posix_time::ptime currentTime;
		currentTime = boost::posix_time::microsec_clock::local_time();
		for (assemblyPacketIt = (*assemblyBufferIt).second.begin();
				assemblyPacketIt != (*assemblyBufferIt).second.end();
				assemblyPacketIt++)
		{
			duration = currentTime -
					(*assemblyPacketIt).second.packetDescription.timeStamp;
			if (duration.total_seconds() > PACKET_TIMEOUT)
			{
				deletePacketFromAssemblyBuffer((*assemblyBufferIt).first);

				mutexAssemblyBuffer.unlock();
			}
		}
		assemblyBufferIt++;
	}
	mutexAssemblyBuffer.unlock();
}
bool Database::checkForPacketInIcnBuffer(ICN_ID icnId)
{
	PACKET_BUFFER_ICN_DEQUE::iterator it;
	Helper h;
	mutexIcnPacketBuffer.lock();
	for(it = icnPacketBuffer.begin(); it != icnPacketBuffer.end(); it++)
	{
		if ((*it).first.compare(icnId) == 0)
		{
			mutexIcnPacketBuffer.unlock();
			return true;
		}
	}
	mutexIcnPacketBuffer.unlock();
	return false;
}
bool Database::checkForPacketInIpBuffer(IP_ADDRESS ipAddress)
{
	PACKET_BUFFER_IP_DEQUE::iterator it;
	Helper h;
	mutexIpPacketBuffer.lock();
	for(it = ipPacketBuffer.begin(); it != ipPacketBuffer.end(); it++)
	{
		if ((*it).first == ipAddress)
		{
			mutexIpPacketBuffer.unlock();
			return true;
		}
	}
	mutexIpPacketBuffer.unlock();
	return false;
}
bool Database::checkFwPolicy(ICN_ID icnId)
{
	Helper helper;
	bool fwPol = false;
	switch(helper.getRootId(icnId))
	{
	case NAMESPACE_IP:
	{
		ICN_ID_DESCRIPTION_IP_MAP::iterator it;
		mutexIpIcnIdDescription.lock();
		it = icnIdDescr.find(icnId);
		if (it != icnIdDescr.end())
		{
			fwPol = (*it).second.fwPolicy;
		}
		mutexIpIcnIdDescription.unlock();
		break;
	}
	case NAMESPACE_HTTP:
	{
		ICN_ID_DESCRIPTION_HTTP_MAP::iterator it;
		mutexHttpIcnIdDescription.lock();
		it = icnIdDescriptionHttp.find(icnId);
		if (it != icnIdDescriptionHttp.end())
		{
			fwPol = (*it).second.forwardingPolicy;
		}
		mutexHttpIcnIdDescription.unlock();
		break;
	}
	}
	return fwPol;
}
void Database::coincidentalMulticastAddNode(URL url, NODE_ID nodeId)
{
	Helper helper;
	COINCIDENTAL_MULTICAST_MAP::iterator it;
	mutexCoincidentalMutlicast.lock();
	it = coincidentalMulticast.find(url);
	if (it == coincidentalMulticast.end())
	{
		list<NODE_ID> l;
		l.push_back(nodeId);
		coincidentalMulticast.insert(pair <URL, list<NODE_ID>>(url, l));
#ifdef DEBUG
		LOG4CXX_DEBUG(_logger, "New coincidental multicast group created for "
				<< "URL " << helper.printIcnId(url));
#endif
	}
	else
	{
		(*it).second.push_back(nodeId);
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Coincidental multicast group updated to "
				<< (*it).second.size() << " members for URL "
				<< helper.printIcnId(url));
#endif
	}
	mutexCoincidentalMutlicast.unlock();
}

bool Database::coincidentalMulticastGetAllNodeIds(URL url,
		list<NODE_ID> &listOfNodeIds)
{
	COINCIDENTAL_MULTICAST_MAP::iterator it;
	Helper helper;
	mutexCoincidentalMutlicast.lock();
	it = coincidentalMulticast.find(url);
	if (it == coincidentalMulticast.end())
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "ICN ID " << helper.printIcnId(url)
				<< " could not be found in coincidental multicast map");
#endif
		mutexCoincidentalMutlicast.unlock();
		return false;
	}
	else
	{
		list<NODE_ID>::iterator itListOfNodeIds;
		for (itListOfNodeIds = (*it).second.begin();
				itListOfNodeIds != (*it).second.end(); itListOfNodeIds++)
		{
			listOfNodeIds.push_back((*itListOfNodeIds));
		}
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Coincidental multicast group for URL "
				<< helper.printIcnId(url) << " released again with "
				<< listOfNodeIds.size() << " member(s)");
#endif
		// Delete entry
		coincidentalMulticast.erase(it);
	}
	mutexCoincidentalMutlicast.unlock();
	return true;
}
void Database::deleteIcnId(ICN_ID icnId)
{
	Helper helper;
	if (!findIcnId(icnId))
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "ICN ID " << helper.printIcnId(icnId)
				<< " could not be found in DB in order to delete it");
#endif
		return;
	}
	switch(helper.getRootId(icnId))
	{
	case NAMESPACE_IP:
	{
		mutexIpIcnIdDescription.lock();
		icnIdDescr.erase(icnId);
		mutexIpIcnIdDescription.unlock();
		break;
	}
	case NAMESPACE_HTTP:
	{
		mutexHttpIcnIdDescription.lock();
		icnIdDescriptionHttp.erase(icnId);
		mutexHttpIcnIdDescription.unlock();
		break;
	}
#ifdef DEBUG
	default:
		LOG4CXX_ERROR(_logger, "Unknown root scope ... cannot delete ICN ID "
				<< helper.printIcnId(icnId));
#endif
	}
#ifdef DEBUG
	LOG4CXX_DEBUG(_logger, "ICN ID " << helper.printIcnId(icnId) << " deleted "
			<< "from database");
#endif
}
void Database::deletePacketFromAssemblyBuffer(string mapKey)
{
	ASSEMBLY_BUFFER_MAP::iterator it;
	mutexAssemblyBuffer.lock();
	it = assemblyBuffer.find(mapKey);
	if (it != assemblyBuffer.end())
	{
		assemblyBuffer.erase(it);
	}
	mutexAssemblyBuffer.unlock();
}
void Database::deletePacketFromIpBuffer(IP_ADDRESS ipAddress)
{
	PACKET_BUFFER_IP_DEQUE::iterator it;
	Helper helper;
	mutexIpPacketBuffer.lock();
	for(it = ipPacketBuffer.begin(); it != ipPacketBuffer.end(); it++)
	{
		if ((*it).first == ipAddress)
		{
			ipPacketBuffer.erase(it);
			mutexIpPacketBuffer.unlock();
			return;
		}
	}
	mutexIpPacketBuffer.unlock();
}
bool Database::findIcnId(ICN_ID icnId) {
	Helper helper;
	switch(helper.getRootId(icnId))
	{
	case NAMESPACE_IP:
	{
		mutexIpIcnIdDescription.lock();
		if (icnIdDescr.find(icnId) != icnIdDescr.end())
		{
			mutexIpIcnIdDescription.unlock();
			return true;
		}
		mutexIpIcnIdDescription.unlock();
		break;
	}
	case NAMESPACE_HTTP:
	{
		mutexHttpIcnIdDescription.lock();
		if (icnIdDescriptionHttp.find(icnId) != icnIdDescriptionHttp.end())
		{
			mutexHttpIcnIdDescription.unlock();
			return true;
		}
		mutexHttpIcnIdDescription.unlock();
	}
	}
	return false;
}

EUI48 Database::generateEui48Address()
{
	ostringstream oss;
	Helper helper;
	int number;
	oss << "0:";
	number = generateUniformRandomNumber(0, 5);
	if (number == 0)
	{
		oss << hex << generateUniformRandomNumber(3, 15);
	}
	else if (number == 5)
	{
		oss << number;
		oss << hex << generateUniformRandomNumber(0, 1);
	}
	else
	{
		oss << number;
		oss << hex << generateUniformRandomNumber(0, 15);
	}
	for (int i=0; i <= 2; i++)
	{
		oss << ":";
		number = generateUniformRandomNumber(0, 15);
		if (number != 0)
			oss << hex << number;
		oss << hex << generateUniformRandomNumber(0, 15);
	}
	oss << ":";
	number = generateUniformRandomNumber(0, 15);
	if (number != 0)
		oss << hex << number;
	oss << hex << generateUniformRandomNumber(0, 15);
#ifdef DEBUG
	LOG4CXX_DEBUG(_logger, "Random MAC generated: " << oss.str());
#endif
	return oss.str();
}
bool Database::getFirstIcnIdFromDatabase(ICN_ID &icnId)
{
	ICN_ID_DESCRIPTION_IP_MAP::iterator it;
	if (icnIdDescr.size() > 0)
	{
		it = icnIdDescr.begin();
		icnId = (*it).first;
		return true;
	}
	return false;
}
int Database::generateUniformRandomNumber(int start, int end)
{
	boost::uniform_int<> dist(start, end);
	boost::variate_generator<BASE_GENERATOR_TYPE&, boost::uniform_int<> > die(getGeneratorReference(), dist);
	return die();
}
bool Database::getEui48ForIp(IP_ADDRESS ipAddress, EUI48 &eui48)
{
	IP_EUI48_MAP::iterator it;
	Helper h;
	mutexArpTable.lock();
	it = arpTable.find(ipAddress);
	if (it == arpTable.end())
	{
		mutexArpTable.unlock();
		return false;
	}
	eui48 = (*it).second;
	mutexArpTable.unlock();
	return true;
}
BASE_GENERATOR_TYPE &Database::getGeneratorReference()
{
	return generator;
}
bool Database::getIcnId(IP_ADDRESS ipAddress, PORT port, ICN_ID &icnId) {
	ICN_ID_DESCRIPTION_IP_MAP::iterator it;
	Helper helper;
	ROUTING_PREFIX routingPrefix;
	if (!getRoutingPrefix(ipAddress, routingPrefix))
		return false;
	icnId = helper.toIcnId(routingPrefix, ipAddress, port);
	mutexIpIcnIdDescription.lock();
	for (it = icnIdDescr.begin(); it != icnIdDescr.end(); it++)
	{
		if ((*it).first.compare(icnId) == 0)
		{
			mutexIpIcnIdDescription.unlock();
			return true;
		}
	}
	mutexIpIcnIdDescription.unlock();
	return false;
}
bool Database::getIcnIdUrl(ICN_ID icnId, ICN_ID &icnIdUrl)
{
	ICN_ID_DESCRIPTION_HTTP_MAP::iterator iterator;
	mutexHttpIcnIdDescription.lock();
	iterator = icnIdDescriptionHttp.find(icnId);
	if (iterator != icnIdDescriptionHttp.end())
	{
		Helper helper;
		string url = (*iterator).second.fqdn;
		url.append((*iterator).second.resource);
		icnIdUrl = helper.toIcnId(NAMESPACE_HTTP, url);
		mutexHttpIcnIdDescription.unlock();
		return true;
	}
	mutexHttpIcnIdDescription.unlock();
	return false;
}
bool Database::getIpAddress(ICN_ID icnId, IP_ADDRESS &ipAddress)
{
	ICN_ID_DESCRIPTION_IP_MAP::iterator it;
	Helper helper;
	if (helper.getRootId(icnId) != NAMESPACE_IP)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Cannot obtain the IP address from ICN ID "
				<< helper.printIcnId(icnId) << " which does not use the IP-over"
				<< "-ICN abstraction");
#endif
		return false;
	}
	mutexIpIcnIdDescription.lock();
	it = icnIdDescr.find(icnId);
	if (it != icnIdDescr.end())
	{
		ipAddress = (*it).second.routingPrefix.networkAddress;
		mutexIpIcnIdDescription.unlock();
		return true;
	}
	// Check if port-less IP is stored as ICN ID
	ostringstream oss;
	oss << helper.getScopePath(icnId, SCOPE_LEVEL_IP_IPADDRESS);
	oss << setfill('0') << setw(ID_LEN) << "0";
	it = icnIdDescr.find(oss.str());
	if (it != icnIdDescr.end())
	{
		ipAddress = (*it).second.routingPrefix.networkAddress;
		mutexIpIcnIdDescription.unlock();
		return true;
	}
	mutexIpIcnIdDescription.unlock();
#ifdef DEBUG
	LOG4CXX_ERROR(_logger, "IP address for ICN ID "
			<< helper.printIcnId(icnId)
			<< " (or its port-less counterpart) could not be found in database");
#endif
	return false;
}

bool Database::getFqdnIpAddressForIcnId(ICN_ID icnId, IP_ADDRESS &ipAddress)
{
	Helper helper;
	ICN_ID_DESCRIPTION_HTTP_MAP::iterator it;
	mutexHttpIcnIdDescription.lock();
	it = icnIdDescriptionHttp.find(icnId);
	if (it != icnIdDescriptionHttp.end())
	{
		ipAddress = (*it).second.ipAddress;
		mutexHttpIcnIdDescription.unlock();
		return true;
	}
	mutexHttpIcnIdDescription.unlock();
#ifdef DEBUG
	LOG4CXX_ERROR(_logger, "ICN ID " << helper.printIcnId(icnId) << " could not"
			<< " be found in DB (HTTP root scope)")
#endif
	return false;
}

int Database::getIcnMtu()
{
	return _icnMtu;
}

int Database::getIpMtu()
{
	return _ipMtu;
}

bool Database::getPacketFromAssemblyBuffer(string mapKey, PACKET *packet)
{
	ASSEMBLY_BUFFER_MAP::iterator assemblyBufferIt;
	mutexAssemblyBuffer.lock();
	assemblyBufferIt = assemblyBuffer.find(mapKey);
	if (assemblyBufferIt != assemblyBuffer.end())
	{
		ASSEMBLY_PACKET_MAP::iterator assemblyPacketIt;
		size_t packetPointer = 0;
		// reassemble packet to packetPointer
		for (assemblyPacketIt = (*assemblyBufferIt).second.begin();
				assemblyPacketIt != (*assemblyBufferIt).second.end();
				assemblyPacketIt++)
		{
			memcpy(packet + packetPointer,
					(*assemblyPacketIt).second.packetDescription.packet,
					(*assemblyPacketIt).second.packetDescription.packetLength);
			packetPointer +=
					(*assemblyPacketIt).second.packetDescription.packetLength;
		}
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Packet of length " << packetPointer
				<< " for key " << (*assemblyBufferIt).first << " reassembled");
#endif
		// Now delete packet
		assemblyBuffer.erase(assemblyBufferIt);
		mutexAssemblyBuffer.unlock();
		return true;
	}
#ifdef DEBUG
	LOG4CXX_ERROR(_logger, "Fragmented packet buffer key " << mapKey << " could"
			<< " not be found in database");
#endif
	mutexAssemblyBuffer.unlock();
	return false;
}
PACKET_LENGTH Database::getPacketLengthFromAssemblyBuffer(string mapKey)
{
	ASSEMBLY_BUFFER_MAP::iterator assemblyBufferIt;
	PACKET_LENGTH packetLength = 0;
	mutexAssemblyBuffer.lock();
	assemblyBufferIt = assemblyBuffer.find(mapKey);
	if (assemblyBufferIt != assemblyBuffer.end())
	{
		ASSEMBLY_PACKET_MAP::iterator fragmentsIt;
		// Check that all sequence numbers are direct successors
		for (fragmentsIt = (*assemblyBufferIt).second.begin();
				fragmentsIt != (*assemblyBufferIt).second.end();
				fragmentsIt++)
		{
			packetLength += (*fragmentsIt).second.packetDescription.packetLength;
		}
	}
	mutexAssemblyBuffer.unlock();
	return packetLength;
}
void Database::getPacketFromIcnBuffer(ICN_ID icnId, PACKET *packet,
		boost::posix_time::ptime &timeStamp)
{
	PACKET_BUFFER_ICN_DEQUE::iterator it;
	Helper h;
	mutexIcnPacketBuffer.lock();
	for(it = icnPacketBuffer.begin(); it != icnPacketBuffer.end(); it++)
	{
		if ((*it).first.compare(icnId) == 0)
		{
			memcpy(packet, it->second.packetDescription.packet,
					(*it).second.packetDescription.packetLength);
			timeStamp = it->second.packetDescription.timeStamp;
			icnPacketBuffer.erase(it);
			mutexIcnPacketBuffer.unlock();
			return;
		}
	}
	mutexIcnPacketBuffer.unlock();
}

void Database::getPacketFromIpBuffer(IP_ADDRESS ipAddress, PACKET *packet,
		boost::posix_time::ptime *timeStamp)
{
	PACKET_BUFFER_IP_DEQUE::iterator it;
	Helper h;
	mutexIpPacketBuffer.lock();
	for(it = ipPacketBuffer.begin(); it != ipPacketBuffer.end(); it++)
	{
		if ((*it).first == ipAddress)
		{
			memcpy(packet, it->second.packetDescription.packet,
					(*it).second.packetDescription.packetLength);
			*timeStamp = it->second.packetDescription.timeStamp;
			ipPacketBuffer.erase(it);
			mutexIpPacketBuffer.unlock();
			return;
		}
	}
	mutexIpPacketBuffer.unlock();
}

PACKET_LENGTH Database::getPacketLength(ICN_ID icnId)
{
	PACKET_BUFFER_ICN_DEQUE::iterator it;
	Helper helper;
	mutexIcnPacketBuffer.lock();
	for(it = icnPacketBuffer.begin(); it != icnPacketBuffer.end(); it++)
	{
		if ((*it).first.compare(icnId) == 0)
		{
			mutexIcnPacketBuffer.unlock();
			return (*it).second.packetDescription.packetLength;
		}
	}
	mutexIcnPacketBuffer.unlock();
	return 0;
}
PACKET_LENGTH Database::getPacketLength(IP_ADDRESS ipAddress)
{
	PACKET_BUFFER_IP_DEQUE::iterator it;
	Helper helper;
	mutexIpPacketBuffer.lock();
	for(it = ipPacketBuffer.begin(); it != ipPacketBuffer.end(); it++)
	{
		if ((*it).first == ipAddress)
		{
			mutexIpPacketBuffer.unlock();
			return (*it).second.packetDescription.packetLength;
		}
	}
	mutexIpPacketBuffer.unlock();
	return 0;
}
PORT_IDENTIFIER Database::getPortIdentifier(ICN_ID icnId)
{
	Helper helper;
	ICN_ID_DESCRIPTION_HTTP_MAP::iterator it;
	it = icnIdDescriptionHttp.find(icnId);
	if (it == icnIdDescriptionHttp.end())
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "PID for ICN ID " << helper.printIcnId(icnId)
				<< " could not be found. Unknown ICN ID");
#endif
		return 0;
	}
	return (*it).second.portIdentifier;
}
bool Database::getRoutingPrefix(ICN_ID icnId, ROUTING_PREFIX &routingPrefix)
{
	string ipAddressString;
	IP_ADDRESS ipAddress;
	Helper helper;
	HASH_STR hash;
	ostringstream oss;
	ipAddressString = helper.getScopeId(icnId, SCOPE_LEVEL_IP_IPADDRESS);
	ipAddress = atoll(ipAddressString.c_str());
	if (!getRoutingPrefix(ipAddress, routingPrefix))
	{// If unknown this is the ICN GW which serves 0.0.0.0
		routingPrefix.networkAddress = 0x0;
		routingPrefix.netmask = 0x0;
		routingPrefix.appliedMask = 0x0;
		oss << dec << routingPrefix.networkAddress;
		routingPrefix.hashedPrefix = hash(oss.str());
		//return false;
	}
	return true;
}
bool Database::getRoutingPrefix(IP_ADDRESS ipAddress,
		ROUTING_PREFIX &routingPrefix)
{
	Helper helper;
	ROUTING_PREFIX_VECTOR::iterator vIt;
	mutexRoutingPrefixes.lock();
	for (vIt = routingPrefixes.begin(); vIt != routingPrefixes.end(); vIt++)
	{
		if ((ipAddress & (*vIt).netmask) == (*vIt).appliedMask)
		{
			routingPrefix = (*vIt);
			mutexRoutingPrefixes.unlock();
			return true;
		}
	}
	mutexRoutingPrefixes.unlock();
	// Ignore special cases when ICN GW boots (don't confuse the users)
	if (ipAddress != 0x0)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Routing prefix for IP address "
				<< helper.printIpAddress(ipAddress) << " not available!");
#endif
	}
	return false;
}
bool Database::getScopePublicationStatus(ICN_ID icnId)
{
	Helper helper;
	switch (helper.getRootId(icnId))
	{
	case NAMESPACE_IP:
	{
		ICN_ID_DESCRIPTION_IP_MAP::iterator it;
		it = icnIdDescr.find(icnId);
		if (it != icnIdDescr.end())
		{
			return (*it).second.scopesPublished;
		}
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "IP namespace-based ICN ID "
				<< helper.printIcnId(icnId)
				<< " could not be found in database");
#endif
		break;
	}
	case NAMESPACE_HTTP:
	{
		ICN_ID_DESCRIPTION_HTTP_MAP::iterator it;
		it = icnIdDescriptionHttp.find(icnId);
		if (it != icnIdDescriptionHttp.end())
		{
			return (*it).second.scopesPublished;
		}
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "HTTP namespace-based ICN ID "
				<< helper.printIcnId(icnId)
				<< " could not be found in database (Size = "
				<< icnIdDescriptionHttp.size() << ")");
#endif
		break;
	}
#ifdef DEBUG
	default:
		LOG4CXX_ERROR(_logger, "Cannot obtain publication status for unknown "
				<< "root scope in ICN ID " << helper.printIcnId(icnId));
#endif
	}
	return false;
}
TRANSPORT_KEY Database::getTransportProtocolKey(ICN_ID icnId)
{
	PACKET_BUFFER_ICN_DEQUE::iterator it;
	mutexIcnPacketBuffer.lock();
	for (it = icnPacketBuffer.begin(); it != icnPacketBuffer.end(); it++)
	{
		if ((*it).first.compare(icnId) == 0)
		{
			TRANSPORT_KEY key = (*it).second.key;
			mutexIcnPacketBuffer.unlock();
			return key;
		}
	}
	mutexIcnPacketBuffer.unlock();
	return 0;
}
void Database::httpPacketBufferCleaner()
{
	Helper helper;
	PACKET_BUFFER_HTTP_DEQUE::iterator it;
	boost::posix_time::ptime currentTime;
	boost::posix_time::time_duration timeDuration;
	currentTime = boost::posix_time::microsec_clock::local_time();
	mutexHttpPacketBuffer.lock();
	for (it = httpPacketBuffer.begin(); it != httpPacketBuffer.end(); it++)
	{
		timeDuration = currentTime - (*it).second.timeStamp;
		if (timeDuration.total_milliseconds() > PACKET_TIMEOUT)
		{
#ifdef DEBUG
			LOG4CXX_TRACE(_logger, "HTTP packet for ICN ID "
					<< helper.printIcnId((*it).first)
					<< " deleted from internal HTTP packet buffer");
#endif
			httpPacketBuffer.erase(it);
		}
	}
	mutexHttpPacketBuffer.unlock();
}
void Database::icnPacketBufferCleaner()
{
	Helper helper;
	PACKET_BUFFER_ICN_DEQUE::iterator it;
	boost::posix_time::ptime currentTime;
	boost::posix_time::time_duration timeDuration;
	currentTime = boost::posix_time::microsec_clock::local_time();
	mutexIcnPacketBuffer.lock();
	for (it = icnPacketBuffer.begin(); it != icnPacketBuffer.end(); it++)
	{
		timeDuration = currentTime - (*it).second.packetDescription.timeStamp;
		if (timeDuration.total_milliseconds() > PACKET_TIMEOUT)
		{
#ifdef DEBUG
			LOG4CXX_TRACE(_logger, "Packet for ICN ID "
					<< helper.printIcnId((*it).first)
					<< " deleted from internal ICN packet buffer");
#endif
			icnPacketBuffer.erase(it);
		}
	}
	mutexIcnPacketBuffer.unlock();
}
bool Database::isIpEndpoint(IP_ADDRESS ipAddress)
{
	IP_ADDRESS_VECTOR_IT it;
	mutexNapIpEndpoints.lock();
	for (it = napIpEndpoints.begin(); it != napIpEndpoints.end(); it++)
	{
		if (*it == ipAddress)
		{
			mutexNapIpEndpoints.unlock();
			return true;
		}
	}
	mutexNapIpEndpoints.unlock();
	return false;
}
void Database::ipPacketBufferCleaner()
{
	Helper helper;
	PACKET_BUFFER_IP_DEQUE::iterator it;
	boost::posix_time::ptime currentTime;
	boost::posix_time::time_duration timeDuration;
	currentTime = boost::posix_time::microsec_clock::local_time();
	mutexIpPacketBuffer.lock();
	for (it = ipPacketBuffer.begin(); it != ipPacketBuffer.end(); it++)
	{
		timeDuration = currentTime - (*it).second.packetDescription.timeStamp;
		if (timeDuration.total_milliseconds() > PACKET_TIMEOUT)
		{
#ifdef DEBUG
			LOG4CXX_TRACE(_logger, "Packet for IP "
					<< helper.printIpAddress((*it).first)
					<< " deleted from internal IP packet buffer");
#endif
			ipPacketBuffer.erase(it);
		}
	}
	mutexIpPacketBuffer.unlock();
}
bool Database::packetReassemblyPossible(string mapKey)
{
	ASSEMBLY_BUFFER_MAP::iterator bufferIt;
	mutexAssemblyBuffer.lock();
	bufferIt = assemblyBuffer.find(mapKey);
	if (bufferIt != assemblyBuffer.end())
	{
		ASSEMBLY_PACKET_MAP::iterator assemblyPacketIt;
		size_t previousSequenceNumber = 0;
		TRANSPORT_STATE transportState = TRANSPORT_STATE_UNKNOWN;
		// Iterator over all received packet fragments
		for (assemblyPacketIt = (*bufferIt).second.begin();
				assemblyPacketIt != (*bufferIt).second.end(); assemblyPacketIt++)
		{
			// First write the lowest sequence number
			if (previousSequenceNumber == 0)
			{
				previousSequenceNumber = (*assemblyPacketIt).first;
				if ((*assemblyPacketIt).second.transportState != TRANSPORT_STATE_START)
				{
					mutexAssemblyBuffer.unlock();
					return false;
				}
			}
			else
			{
				// if a fragment is still missing, end here
				if ((*assemblyPacketIt).first != (previousSequenceNumber + 1))
				{
					mutexAssemblyBuffer.unlock();
					return false;
				}
				previousSequenceNumber = (*assemblyPacketIt).first;
				transportState = (*assemblyPacketIt).second.transportState;
			}
		}
		// Last fragment has not been received
		if (transportState != TRANSPORT_STATE_FINISHED)
		{
			mutexAssemblyBuffer.unlock();
			return false;
		}
	}
	mutexAssemblyBuffer.unlock();
	return true;
}
void Database::setFwPolicy(ICN_ID icnId, bool policy)
{
	Helper helper;
	switch(helper.getRootId(icnId))
	{
	case NAMESPACE_IP:
	{
		ICN_ID_DESCRIPTION_IP_MAP::iterator it;
		mutexIpIcnIdDescription.lock();
		it = icnIdDescr.find(icnId);
		if (it != icnIdDescr.end())
		{
			(*it).second.fwPolicy = policy;
			mutexIpIcnIdDescription.unlock();
#ifdef DEBUG
			if (policy)
			{
				LOG4CXX_DEBUG(_logger, "Forwarding policy for ICN ID "
						<< helper.printIcnId(icnId)
						<< " was updated to 'enabled' (IP namespace)");
			}
			else
			{
				LOG4CXX_DEBUG(_logger, "Forwarding policy for ICN ID "
						<< helper.printIcnId(icnId)
						<< " was update to 'disabled' (IP namespace)");
			}
#endif
			return;
		}
		mutexIpIcnIdDescription.unlock();
		break;
	}
	case NAMESPACE_HTTP:
	{
		ICN_ID_DESCRIPTION_HTTP_MAP::iterator it;
		mutexIpIcnIdDescription.lock();
		it = icnIdDescriptionHttp.find(icnId);
		if (it != icnIdDescriptionHttp.end())
		{
			(*it).second.forwardingPolicy = policy;
			mutexIpIcnIdDescription.unlock();
#ifdef DEBUG
			if (policy)
			{
				LOG4CXX_DEBUG(_logger, "Forwarding policy for ICN ID "
						<< helper.printIcnId(icnId)
						<< " was updated to 'enabled' (HTTP namespace)");
			}
			else
			{
				LOG4CXX_DEBUG(_logger, "Forwarding policy for ICN ID "
						<< helper.printIcnId(icnId)
						<< " was update to 'disabled' (HTTP namespace)");
			}
#endif
			return;
		}
		break;
	}
#ifdef DEBUG
	default:
		LOG4CXX_ERROR(_logger, "Could not update forwarding policy for ICN ID "
				<< helper.printIcnId(icnId) << ". Unknown root namespace");
#endif
	}
#ifdef DEBUG
	LOG4CXX_ERROR(_logger, "ICN ID " << icnId
			<< " could not be found in DB for checking its forwarding policy"
			<< " state. This must not happen");
#endif
}

void Database::setIcnMtu(int mtu)
{
	_icnMtu = mtu;
}

void Database::setIpMtu(int mtu)
{
	_ipMtu = mtu;
}

void Database::setScopePublicationStatus(ICN_ID icnId, bool status)
{
	Helper helper;
	switch(helper.getRootId(icnId))
	{
	case NAMESPACE_IP:
	{
		ICN_ID_DESCRIPTION_IP_MAP::iterator it;
		mutexIpIcnIdDescription.lock();
		it = icnIdDescr.find(icnId);
		if (it != icnIdDescr.end())
		{
			(*it).second.scopesPublished = status;
		}
#ifdef DEBUG
		else
		{
			LOG4CXX_ERROR(_logger, "ICN ID (IP namespace) "
					<< helper.printIcnId(icnId) << " could not be found in "
					<< "database to update scope publication status");
		}
#endif
		mutexIpIcnIdDescription.unlock();
		break;
	}
	case NAMESPACE_HTTP:
	{
		ICN_ID_DESCRIPTION_HTTP_MAP::iterator it;
		mutexHttpIcnIdDescription.lock();
		it = icnIdDescriptionHttp.find(icnId);
		if (it != icnIdDescriptionHttp.end())
		{
			(*it).second.scopesPublished = status;
		}
#ifdef DEBUG
		else
		{
			LOG4CXX_ERROR(_logger, "ICN ID (HTTP namespace) "
					<< helper.printIcnId(icnId) << " could not be found in "
					<< "database to update scope publication status");
		}
#endif
		mutexHttpIcnIdDescription.unlock();
		break;
	}
#ifdef DEBUG
	default:
		LOG4CXX_ERROR(_logger, "Cannot update the scope publication status. "
				<< "Unknown root namespace " << helper.getRootId(icnId));
#endif
	}
}
bool Database::testIpAgainstRoutingPrefix(IP_ADDRESS ipAddress,
		ROUTING_PREFIX routingPrefix)
{
	Helper helper;
	if ((routingPrefix.networkAddress & routingPrefix.netmask) ==
			(ipAddress & routingPrefix.netmask))
	{
#ifdef DEBUG
		LOG4CXX_TRACE(_logger, "Matched IP address "
				<< helper.printIpAddress(ipAddress) << " with routing prefix "
				<< helper.printRoutingPrefix(routingPrefix));
#endif
		return true;
	}
	return false;
}
