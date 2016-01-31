/*
 * httphandler.cc
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

#include "httphandler.hh"
#include "../helper.hh"
HttpHandler::~HttpHandler() {
	// TODO Auto-generated destructor stub
}

void HttpHandler::operator()()
{
#ifdef DEBUG
#ifdef TRACE
	Transport transport(_nbBlackadder, _logger, _trace, _db);
#else
	Transport transport(_nbBlackadder, _logger, _db);
#endif
#else
#ifdef TRACE
	Transport transport(_nbBlackadder, _trace, _db);
#else
	Transport transport(_nbBlackadder, _db);
#endif
#endif
	Helper helper;
#ifdef TRACE
	_trace.writeTrace(_httpMethod, _fqdn, _resource, _packetCaptureTimeStamp);
#endif
	PACKET *packet;
	PACKET_LENGTH packetLength = sizeof(HTTP_METHOD)
			+ sizeof(FQDN_LENGTH) + _fqdn.length()
			+ sizeof(RESOURCE_LENGTH) + _resource.length()
			+ sizeof(PACKET_LENGTH) + _payloadLength;
	RESOURCE_LENGTH resourceLength = _resource.length();
	FQDN_LENGTH fqdnLength = _fqdn.length();
	packet = (PACKET *)malloc(packetLength);
	// Adding HTTP method
	memcpy(packet, &_httpMethod, sizeof(_httpMethod));
	// Adding FQDN length
	memcpy(packet + sizeof(HTTP_METHOD), &fqdnLength,
			sizeof(FQDN_LENGTH));
	// Adding FQDN
	memcpy(packet + sizeof(HTTP_METHOD) + sizeof(FQDN_LENGTH),
			_fqdn.c_str(), fqdnLength);
	// Adding resource length
	memcpy(packet + sizeof(HTTP_METHOD) + sizeof(FQDN_LENGTH) + fqdnLength,
			&resourceLength, sizeof(RESOURCE_LENGTH));
	// Adding resource
	memcpy(packet + sizeof(HTTP_METHOD) + sizeof(FQDN_LENGTH) + fqdnLength
			+ sizeof(RESOURCE_LENGTH),	_resource.c_str(), resourceLength);
	// Adding HTTP packet length
	memcpy(packet + sizeof(HTTP_METHOD) + sizeof(FQDN_LENGTH) + fqdnLength
			+ sizeof(RESOURCE_LENGTH) + resourceLength, &_payloadLength,
			sizeof(PACKET_LENGTH));
	// Adding entire HTTP request packet
	memcpy(packet + sizeof(HTTP_METHOD) + sizeof(FQDN_LENGTH) + fqdnLength
			+ sizeof(RESOURCE_LENGTH) + resourceLength + sizeof(PACKET_LENGTH),
			_payload, _payloadLength);
	if (_httpMethod < 100)
	{
		string url = _fqdn;
		url.append(_resource);
		ICN_ID icnIdFqdn = helper.toIcnId(NAMESPACE_HTTP, _fqdn);
		ICN_ID icnIdUrl = helper.toIcnId(NAMESPACE_HTTP, url);
		_db.addIcnId(icnIdFqdn, _fqdn, _resource);
		_db.addIcnId(icnIdUrl, _fqdn, _resource, _portIdentifier);
		// If ICN ID has not been published to RV, do it now & add packet to buffer
		if (!_db.getScopePublicationStatus(icnIdFqdn))
		{
			string id, prefixId;
			prefixId = helper.getScopeId(icnIdFqdn, SCOPE_LEVEL_HTTP_ROOT);
			_db.addPacketToIcnBuffer(icnIdFqdn, _key, packet, packetLength,
					_packetCaptureTimeStamp);
			// Advertising data available under HTTP/FQDN.
			id = helper.getScopeId(icnIdFqdn, SCOPE_LEVEL_HTTP_FQDN_iITEM);
			prefixId = helper.getScopePath(icnIdFqdn, SCOPE_LEVEL_HTTP_FQDN);
			_nbBlackadder->publish_info(hex_to_chararray(id),
					hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL, 0);
#ifdef DEBUG
			LOG4CXX_DEBUG(_logger, "New FQDN information item <" << id
					<< "> advertised under father scope "
					<< helper.printIcnId(prefixId));
#endif
			_db.setScopePublicationStatus(icnIdFqdn, true);
			return;
		}
		// If forwarding policy is disabled, add packet to HTTP packet buffer
		if (!_db.checkFwPolicy(icnIdFqdn))
		{
			_db.addPacketToIcnBuffer(icnIdFqdn, packet, packetLength,
					_packetCaptureTimeStamp);
			return;
		}
		transport.publishDataiSub(icnIdFqdn, icnIdUrl, _key, packet,
				packetLength, _packetCaptureTimeStamp);
	}
#ifdef DEBUG
	else
	{
		LOG4CXX_ERROR(_logger, "The HTTP handler must not receive HTTP response"
				<< " packets");
	}
#endif
}
