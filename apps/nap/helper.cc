/*
 * helper.cc
 *
 *  Created on: 30 Apr 2015
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

#include <boost/algorithm/string.hpp>
#include <iostream>
#include <functional>
#include <arpa/inet.h>
#include <tgmath.h>
#include "helper.hh"
Helper::Helper() {
	// TODO Auto-generated constructor stub

}

Helper::~Helper() {
	// TODO Auto-generated destructor stub
}
IP_ADDRESS Helper::getIpAddress(ICN_ID icnId)
{
	string ipAddressString;
	ipAddressString = getScopeId(icnId, SCOPE_LEVEL_IP_IPADDRESS);
	return atoll(ipAddressString.c_str());
}
uint16_t Helper::getRootId(ICN_ID icnId)
{
	ostringstream oss;
	for (int i = 0; i < ID_LEN; ++i)
	{
			oss << icnId[i];
	}
	return atoi(oss.str().c_str());
}
ICN_ID Helper::getScopeId(ICN_ID icnId, uint16_t scopeLevel)
{
	Helper helper;
	ostringstream oss, scopeId;
	int start = 0;
	int end = 0;
	switch (helper.getRootId(icnId))
	{
	case NAMESPACE_IP:
	{
		if (scopeLevel == SCOPE_LEVEL_IP_ROOT)
		{
			start = 0;
			end = ID_LEN;
		}
		else if (scopeLevel == SCOPE_LEVEL_IP_PREFIX)
		{
			start = ID_LEN;
			end = start + ID_LEN;
		}
		else if (scopeLevel == SCOPE_LEVEL_IP_IPADDRESS)
		{
			start = 2 * ID_LEN;
			end = start + ID_LEN;
		}
		else if (scopeLevel == SCOPE_LEVEL_IP_PORT)
		{
			start = 3 * ID_LEN;
			end = start + ID_LEN;
		}
		// Now stream the values into a stringstream
		for (int i = start; i < end; ++i)
		{
				oss << icnId[i];
		}
		break;
	}
	case NAMESPACE_HTTP:
	{
		if (scopeLevel == SCOPE_LEVEL_HTTP_ROOT)
		{
			start = 0;
			end = ID_LEN;
		}
		else if (scopeLevel == SCOPE_LEVEL_HTTP_FQDN)
		{
			start = ID_LEN;
			end = icnId.size();
		}
		else if (scopeLevel == SCOPE_LEVEL_HTTP_FQDN_iITEM)
		{
			start = icnId.size() - ID_LEN;
			end = icnId.size();
		}
		else if (scopeLevel == SCOPE_LEVEL_HTTP_URL)
		{
			start = ID_LEN;
			end = icnId.size();
		}
		else if (scopeLevel == SCOPE_LEVEL_HTTP_URL_iITEM)
		{
			start = icnId.size() - ID_LEN;
			end = icnId.size();
		}
		else if (scopeLevel == SCOPE_LEVEL_HTTP_ANY)
		{
			start = ID_LEN;
			end = icnId.size() - ID_LEN;
			// if start == end, there's not scope level between root and iItem
			// return root scope instead
			if (start == end)
				start = 0;
		}
		else if (scopeLevel == SCOPE_LEVEL_HTTP_ANY_iITEM)
		{
			start = icnId.size() - ID_LEN;
			end = icnId.size();
		}
		// Now stream the values into a stringstream
		for (int i = start; i < end; ++i)
		{
			oss << icnId[i];
		}
		break;
	}
	default:
		oss << "UNKNOWN NAMESPACE";
	}
	return oss.str();
}
ICN_ID Helper::getScopePath(ICN_ID icnId, uint16_t scopeLevel)
{
	ostringstream scopePath;
	Helper helper;
	switch(helper.getRootId(icnId))
	{
	case NAMESPACE_IP:
	{
		int scopeLevelIt = 0;
		while (scopeLevelIt <= scopeLevel)
		{
			scopePath << getScopeId(icnId, scopeLevelIt);
			scopeLevelIt++;
		}
		break;
	}
	case NAMESPACE_HTTP:
	{
		size_t iterator;
		size_t stop;
		// Only the root scope
		if (SCOPE_LEVEL_HTTP_ROOT)
		{
			iterator = 0;
			stop = ID_LEN;
		}
		// The entire scope path except the information item
		else if (SCOPE_LEVEL_HTTP_FQDN || SCOPE_LEVEL_HTTP_URL)
		{
			iterator = 0;
			stop = icnId.size() - ID_LEN;
		}
		while (iterator < stop)
		{
			scopePath << icnId[iterator];
			iterator++;
		}
		break;
	}
	default:
		scopePath << "";
	}
	return scopePath.str();
}
EUI48 Helper::macToEui48(char * mac)
{
	vector<string> v;
	vector<string>::iterator vIt;
	ostringstream oss;
	boost::split(v, mac, boost::is_any_of(":"));
	oss << setw(2) << setfill('0');
	for (vIt = v.begin(); vIt != v.end(); vIt++)
		oss << (*vIt).c_str();
	return oss.str();
}
string Helper::printEui48(EUI48 eui48)
{
	ostringstream oss;
	/*for (size_t i = 0; i <= floor(eui48.size() / 2) - 1; i++)
		oss << eui48.at(2*i) << eui48.at(2*i + 1) << ":";
	oss << eui48.at(11) << eui48.at(12);
	*/
	oss << eui48;
	return oss.str();
}
string Helper::printIcnId(ICN_ID icnId)
{
	ostringstream oss;
	Helper helper;
	oss << "<";
	size_t i = 0;
	while (i < icnId.length())
	{
		if ((i % ID_LEN) == 0)
		{
			oss << "/";
		}
		oss << icnId[i];
		i++;
	}
	oss << ">";
	return oss.str();
}
string Helper::printIpAddress(IP_ADDRESS ipAddress)
{
	char srcIp[256];
	ostringstream oss;
	struct in_addr address;
	address.s_addr = ipAddress;
	strcpy(srcIp, inet_ntoa(address));
	oss << srcIp;
	return oss.str();
}
string Helper::printNetmask(NETMASK netmask)
{
	char mask[256];
	ostringstream oss;
	vector<string> v;
	vector<string>::iterator vIt;
	struct in_addr address;
	address.s_addr = netmask;
	strcpy(mask, inet_ntoa(address));
	oss << mask;
	return oss.str();
}
string Helper::printPort(PORT port)
{
	ostringstream oss;
	oss << ntohs(port);
	return oss.str();
}
string Helper::printRoutingPrefix(ROUTING_PREFIX routingPrefix)
{
	ostringstream oss;
	oss << printIpAddress(routingPrefix.networkAddress) << "/"
			<< printNetmask(routingPrefix.netmask);
	return oss.str();
}
string Helper::printScopePath(ICN_ID icnId, uint8_t scopeLevel)
{
	Helper helper;
	ostringstream oss;
	oss << "</";
	switch (helper.getRootId(icnId))
	{
	case NAMESPACE_IP:
	{
		uint8_t scopeLevelIt = 0;
		while (scopeLevelIt <= scopeLevel)
		{
			oss << getScopeId(icnId, scopeLevelIt);
			if (scopeLevelIt != scopeLevel)
				oss << "/";
			scopeLevelIt++;
		}
		break;
	}
	case NAMESPACE_HTTP:
	{
		break;
	}
	default:
		oss << "UNKNOWN NAMESPACE";
	}
	oss << ">";
	return oss.str();
}

ICN_ID Helper::toIcnId(ROUTING_PREFIX routingPrefix, IP_ADDRESS ipAddress,
		PORT port)
{
	HASH_STR hashStr;
	ostringstream oss;
	ostringstream rp;
	ostringstream hashedId;
	// ICN Namespace scope ID
	oss << setw(ID_LEN) << setfill('0') << NAMESPACE_IP;
	// Prefix scope ID
	rp << dec << routingPrefix.networkAddress;// << routingPrefix.netmask;
	if (rp.str().length() > ID_LEN)
	{
		hashedId << hashStr(rp.str());
	}
	else
	{
		hashedId << routingPrefix.networkAddress;
	}
	//oss << setw((int)(ceil((float)hashedId.str().length() / ID_LEN)) * ID_LEN)
	//		<< setfill('0') << hashedId.str();
	oss << setw(ID_LEN) << setfill('0') << hashedId.str();
	rp.str("");
	rp.flush();
	// IP address scope ID
	rp << dec << ipAddress;
	oss << setw(ID_LEN) << setfill('0') << rp.str();
	// Port scope ID
	oss << setw(ID_LEN) << setfill('0') << port;
	return oss.str();
}
ICN_ID Helper::toIcnId(uint16_t icnNamespace, string str)
{
	ostringstream oss;
	string hashedString;
	HASH_STR hashStr;
	switch(icnNamespace)
	{
	case NAMESPACE_HTTP:
	{
		oss << hashStr(str);
		hashedString = oss.str();
		oss.str("");
		oss.flush();
		oss << setw(ID_LEN) << setfill('0') << NAMESPACE_HTTP;
		unsigned int scopeLevels =
				ceil((double)hashedString.size() / (double)ID_LEN);
		// first fill up with 0s
		for (size_t i = 0; i < (scopeLevels * ID_LEN - hashedString.length()); i++)
			oss << "0";
		// now append the hashed string
		for (size_t i = 0; i < hashedString.length(); i++)
			oss << hashedString[i];
		break;
	}
	default:
		oss << "";
	}
	return oss.str();
}
string Helper::toMapKey(ICN_ID icnId, TRANSPORT_KEY key)
{
	return toMapKey(icnId, "00000000", key);
}
string Helper::toMapKey(ICN_ID icnId, string nodeId, TRANSPORT_KEY key)
{
	ostringstream oss;
	oss << icnId << nodeId << key;
	return oss.str();
}
