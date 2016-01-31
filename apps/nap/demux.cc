/*
 * demux.cc
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

#include "demux.hh"
#include "handlers/iphandler.hh"
#include "handlers/httphandler.hh"
#include "listeners/arplistener.hh"
#include "helper.hh"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ether.h>
/*void captureCallbackHandler(unsigned char * user, const struct pcap_pkthdr *header, const u_char *packet)
{
    ((Demux*) user)->processPacket(user, header, packet);
}*/

Demux::~Demux() { }

void Demux::changeSchedulerParameters(boost::thread &demuxThread)
{
	int retcode;
	int policy;

	pthread_t threadID = (pthread_t) demuxThread.native_handle();
	struct sched_param param;

	if ((retcode = pthread_getschedparam(threadID, &policy, &param)) != 0)
	{
		errno = retcode;
#ifdef DEBUG /* DEBUG start */
		LOG4CXX_ERROR(_logger, "Could not get demux's thread parameters ("
				<< "PID " << getpid() << ", Thread ID " << threadID << ")");
		perror("pthread_getschedparam");
	}
	else
	{
		LOG4CXX_DEBUG(_logger, "Demux thread parameters: " << "policy="
				<< ((policy == SCHED_FIFO)  ? "SCHED_FIFO" :
						(policy == SCHED_RR)    ? "SCHED_RR" :
						(policy == SCHED_OTHER) ? "SCHED_OTHER" :
						"???") << ", priority=" << param.sched_priority);
	}
#else /* DEBUG else */
	}
#endif /* DEBUG end */
	policy = SCHED_OTHER;
	param.sched_priority = _db.threadPriority;
	if ((retcode = pthread_setschedparam(threadID, policy, &param)) != 0)
	{
		errno = retcode;
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Could not set demux's thread parameters ("
				<< "PID " << getpid() << ", Thread ID " << threadID << ")");
		perror("pthread_setschedparam");
	}
	else
	{
		LOG4CXX_DEBUG(_logger, "Demux thread parameters changed: " << "policy="
						<< ((policy == SCHED_FIFO)  ? "SCHED_FIFO" :
								(policy == SCHED_RR)    ? "SCHED_RR" :
								(policy == SCHED_OTHER) ? "SCHED_OTHER" :
								"???") << ", priority=" << param.sched_priority);
	}
#else
	}
#endif
}
void Demux::operator()() {
	char errbuf[PCAP_ERRBUF_SIZE];	/*!< Error string */
	PCAP_HANDLER * pcapHandler;
	Helper helper;
	string id;
	string prefixId;
	ICN_ID icnId;
	ostringstream oss;
	// TODO implement proper kernel ARP table cleaning
	oss << "for arpitem in `arp -n | grep " << _device
			<< " | awk '{print $1}'`; do arp -d $arpitem; done";
#ifdef DEBUG
	LOG4CXX_DEBUG(_logger, "Flushing local ARP table entries for device "
			<< _device);
#endif
	int i = system (oss.str().c_str());
	if (i != 0)
	{
#ifdef DEBUG
		LOG4CXX_ERROR(_logger, "Flushing ARP table for device " << _device
				<< " failed. Lemme try something else ...");
#endif
		oss.str("");
		oss << "ifconfig " << _device << " down && ifconfig " << _device
				<< " up";
		i = system (oss.str().c_str());
		if (i != 0)
		{
#ifdef DEBUG
			LOG4CXX_FATAL(_logger, "This went horribly wrong ... please hit "
					<< "Ctrl+C and clean the ARP table manually");
#endif
			return;
		}
	}
	// More info abt the pcap fields here: http://www.tcpdump.org/pcap3_man.html
	// _device: the interface on which libpcap should sniff
	// MAX_MESSAGE_PAYLOAD: the max size of the memory for a single packet
	// 1: promiscous mode
	// 0: Readout time delay to decrease CPU load (adds delay if not 0!)
	// errbuf: Error string
	pcapHandler = pcap_open_live(_device, MAX_MESSAGE_PAYLOAD, 1, 0, errbuf);
	if (pcapHandler == NULL)
	{
#ifdef DEBUG
		LOG4CXX_FATAL(_logger, "Cannot open listener on " << _device);
#endif
		return;
	}
	_pcapHandler = pcapHandler;
#ifdef DEBUG
	LOG4CXX_INFO(_logger, "Demux started on device " << _device);
#endif
	// Creating IP scope tree for this NAP and subscribe to all data published
	// underneath. Note the IP address is not used to create the scope branch
	icnId = helper.toIcnId(_db.hostRoutingPrefix,
			_db.hostNetworkAddress, PORT_UNKNOWN);
	// Publish root scope
	id = helper.getScopePath(icnId, SCOPE_LEVEL_IP_ROOT);
	prefixId = string();
	_nbBlackadder->publish_scope(hex_to_chararray(id),
			hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL,	0);
#ifdef DEBUG
	LOG4CXX_DEBUG(_logger, "Published new IP root scope " << helper.printScopePath(
			icnId, SCOPE_LEVEL_IP_ROOT));
#endif
	// Publish prefix scope under root scope
	id = helper.getScopeId(icnId, SCOPE_LEVEL_IP_PREFIX);
	prefixId = helper.getScopePath(icnId, SCOPE_LEVEL_IP_ROOT);
	_nbBlackadder->publish_scope(hex_to_chararray(id),
			hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL,	0);
#ifdef DEBUG
	LOG4CXX_DEBUG(_logger, "Published new scope <" << id
			<< "> under IP root scope " << helper.printScopePath(icnId,
					SCOPE_LEVEL_IP_ROOT));
#endif
	// Publish IP scope for host-based deployments
	if (_db.hostNetworkAddress != _db.hostRoutingPrefix.networkAddress)
	{
		id = helper.getScopeId(icnId, SCOPE_LEVEL_IP_IPADDRESS);
		prefixId = helper.getScopePath(icnId, SCOPE_LEVEL_IP_PREFIX);
		_nbBlackadder->publish_scope(hex_to_chararray(id),
				hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL,	0);
#ifdef DEBUG
		LOG4CXX_DEBUG(_logger, "Published new scope <" << id
				<< "> under father scope " << helper.printScopePath(icnId,
						SCOPE_LEVEL_IP_PREFIX));
		LOG4CXX_DEBUG(_logger, "Subscribing to all items published under "
				<< helper.printScopePath(icnId, SCOPE_LEVEL_IP_IPADDRESS));
#endif
	}
	// Subscribe to all items published under IP root scope / prefix scope
	else
	{
		// Subscribe to all items published under IP root scope / prefix scope
		id = helper.getScopeId(icnId, SCOPE_LEVEL_IP_PREFIX);
		prefixId = helper.getScopePath(icnId, SCOPE_LEVEL_IP_ROOT);
#ifdef DEBUG
		LOG4CXX_DEBUG(_logger, "Subscribing to all scopes published under "
				<< helper.printScopePath(icnId, SCOPE_LEVEL_IP_PREFIX));
#endif
	}
	_nbBlackadder->subscribe_scope(hex_to_chararray(id),
			hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL,	0);
	// Start sniffing for packets
//	Demux* pDemux = this;
//	pcap_loop(pcapHandler, -1, (pcap_handler)captureCallbackHandler,
//			(u_char*)pDemux);
	const u_char *packet;
	struct pcap_pkthdr h;
	while (_db.runNap)
	{
		packet = pcap_next(pcapHandler, &h);
		if (packet != NULL)
		{
			processPacket(&h, packet);
		}
	}
#ifdef DEBUG
	LOG4CXX_INFO(_logger, "Closing capturing device " << _device);
#endif
	shutdown();
}
/*void Demux::processPacket(u_char *args,const struct pcap_pkthdr *header,
		const u_char *packet)*/
void Demux::processPacket(const struct pcap_pkthdr *header, const u_char *packet)
{
	// ### Debugging code for PCAP capturing delay investigation
	//char buffer[30];
	//struct timeval tv;
	//time_t curtime;
	//gettimeofday(&tv, NULL);
	//curtime=tv.tv_sec;
	//strftime(buffer,30,"%m-%d-%Y  %T.",localtime(&curtime));
	//printf("Delay = %d us\n", tv.tv_usec - header->ts.tv_usec);
	// ###
	Helper helper;
	int linkHdrLen = 14;
	struct ip *ipHeader;
	struct ether_header *eptr;
	IP_ADDRESS srcIp, dstIp;
	boost::posix_time::ptime incomingPacketTimestamp;
	incomingPacketTimestamp = boost::posix_time::microsec_clock::local_time();
	eptr = (struct ether_header *) packet;
	switch (ntohs(eptr->ether_type))
	{
		// IP packet inside Ethernet frame
		case ETHERTYPE_IP:
		{
			PORT portDestination = PORT_UNKNOWN;
			packet += linkHdrLen; // Skipping Ethernet header
			ipHeader = (struct ip *)packet;
			srcIp = ipHeader->ip_src.s_addr;
			dstIp = ipHeader->ip_dst.s_addr;
			// Ignore IP packet sent by this machine to one of the IP endpoints
			if (srcIp == _db.hostIpAddressDevice)
			{
				EUI48 macAddress;
				packet -= linkHdrLen;
				macAddress = ether_ntoa((struct ether_addr *)&eptr->ether_dhost);
				_db.addIpEui48Pair(dstIp, macAddress);
				return;
			}
			// Ignore decapsulated IP packet sent to one of the NAP's IP endpoints
			if (_db.isIpEndpoint(dstIp))
			{
#ifdef DEBUG
				LOG4CXX_TRACE(_logger, "Ignoring packet sent to one of the "
						<< "NAP's IP endpoints" << " on IP "
						<< helper.printIpAddress(dstIp));
#endif
				return;
			}
			// Ignore IP packet sent by one of the IP endpoints to the NAP
			if (dstIp == _db.hostIpAddressDevice)
			{
				Helper helper;
				_db.addIpEndpoint(dstIp);
#ifdef DEBUG
				LOG4CXX_TRACE(_logger, "Ignoring IP packet "
						<< helper.printIpAddress(srcIp) << " -> "
						<< helper.printIpAddress(dstIp) << " targeted directly"
						<< " to the NAP from an IP endpoint");
#endif
				return;
			}
			// Ignore IP packet meant for another machine in the same subnet as
			// the NAP's interface
			if (!_db.icnGateway
					&& _db.hostNetmask != 0xffffffff
					&& _db.testIpAgainstRoutingPrefix(dstIp, _db.hostRoutingPrefix))
			{
				Helper helper;
#ifdef DEBUG
				LOG4CXX_TRACE(_logger, "Ignoring IP packet of length "
						<< ntohs(ipHeader->ip_len) << " sent from "
						<< helper.printIpAddress(srcIp) << " to another "
						<< "machine in the NAP's prefix "
						<< helper.printRoutingPrefix(_db.hostRoutingPrefix));
#endif
				return;
			}
			// If packet was sent by other machine towards the Internet
			ROUTING_PREFIX prefix;
			_db.getRoutingPrefix(dstIp, prefix);
			if (_db.icnGateway && prefix.appliedMask == 0x0)
			{
#ifdef DEBUG
				LOG4CXX_TRACE(_logger, "Ignoring IP packet from "
						<< helper.printIpAddress(srcIp) << " sent towards the "
						<< "Internet");
#endif
				_db.addIpEndpoint(dstIp);
				return;
			}
#ifdef DEBUG
			int ttl = ipHeader->ip_ttl;
			int ipHeaderLength = 4*ipHeader->ip_hl;
			LOG4CXX_TRACE(_logger, "IP packet received with header: "
					<< "SRC: " << helper.printIpAddress(srcIp)
					<< "\tDST: " << helper.printIpAddress(dstIp)
					<< "\tID: " << ntohs(ipHeader->ip_id)
					<< "\tTOS: " << ntohs(ipHeader->ip_tos)
					<< "\tTTL: " << ttl
					<< "\tIP HL: " << ipHeaderLength
					<< "\tPayload Length: " << ntohs(ipHeader->ip_len));
#endif
			packet -= linkHdrLen;
			_db.addIpEui48Pair(ipHeader->ip_src.s_addr,
					ether_ntoa((struct ether_addr *)&eptr->ether_shost));
			packet += linkHdrLen;
			packet += 4*ipHeader->ip_hl;
			if (ipHeader->ip_p == IPPROTO_TCP)
			{
				struct tcphdr *tcpHeader;
				tcpHeader = (struct tcphdr*)packet;
#ifdef DEBUG
				switch(ntohs(tcpHeader->dest))
				{
				case PORT_HTTP:
				{
					LOG4CXX_TRACE(_logger, "TCP Header: "
							<< "Src Port=" << ntohs(tcpHeader->source)
							<< "\tDst Port=" << ntohs(tcpHeader->dest)
							<< " (HTTP)"
							<< "\tSeq=" << ntohl(tcpHeader->seq)
							<< "\tAckSeq=" << ntohl(tcpHeader->ack_seq)
							<< "\tWindow=" << ntohs(tcpHeader->window)
							<< "\tTCP Length=" << 4 * tcpHeader->doff
							);// -> dropping packet, as proxy will "
							//<< "take care of it");
					if (_logger->getEffectiveLevel()->toInt() <= TRACE_INT)
					{
						printf("\tTCP Flags: %c%c%c%c%c%c\n",
								(tcpHeader->urg ? 'U' : '_'),
								(tcpHeader->ack ? 'A' : '_'),
								(tcpHeader->psh ? 'P' : '_'),
								(tcpHeader->rst ? 'R' : '_'),
								(tcpHeader->syn ? 'S' : '_'),
								(tcpHeader->fin ? 'F' : '_'));
					}
					break;
					//return;
				}
				case PORT_NETBIOS:
				{
					LOG4CXX_TRACE(_logger, "TCP Header: "
							<< "Src Port:" << ntohs(tcpHeader->source)
							<< "\tDst Port:" << ntohs(tcpHeader->dest)
							<< " (NETBIOS)"
							<< "\tSeq=" << ntohl(tcpHeader->seq)
							<< "\tAckSeq=" << ntohl(tcpHeader->ack_seq)
							<< "\tWindow=" << ntohs(tcpHeader->window)
							<< "\tTCP Length=" << 4 * tcpHeader->doff);
					break;
				}
				case PORT_HTTPS:
				{
					LOG4CXX_TRACE(_logger, "TCP Header: "
							<< "Src Port:" << ntohs(tcpHeader->source)
							<< "\tDst Port:" << ntohs(tcpHeader->dest)
							<< " (HTTPS)"
							<< "\tSeq=" << ntohl(tcpHeader->seq)
							<< "\tAckSeq=" << ntohl(tcpHeader->ack_seq)
							<< "\tWindow=" << ntohs(tcpHeader->window)
							<< "\tTCP Length=" << 4 * tcpHeader->doff);
					break;
				}
				case PORT_RTP_MEDIA:
				{
					LOG4CXX_TRACE(_logger, "TCP Header: "
							<< "Src Port:" << ntohs(tcpHeader->source)
							<< "\tDst Port:" << ntohs(tcpHeader->dest)
							<< " (RTP Media)"
							<< "\tSeq=" << ntohl(tcpHeader->seq)
							<< "\tAckSeq=" << ntohl(tcpHeader->ack_seq)
							<< "\tWindow=" << ntohs(tcpHeader->window)
							<< "\tTCP Length=" << 4 * tcpHeader->doff);
					break;
				}
				case PORT_RTP_CONTROL:
				{
					LOG4CXX_TRACE(_logger, "TCP Header: "
							<< "Src Port:" << ntohs(tcpHeader->source)
							<< "\tDst Port:" << ntohs(tcpHeader->dest)
							<< " (RTP control protocol)"
							<< "\tSeq=" << ntohl(tcpHeader->seq)
							<< "\tAckSeq=" << ntohl(tcpHeader->ack_seq)
							<< "\tWindow=" << ntohs(tcpHeader->window)
							<< "\tTCP Length=" << 4 * tcpHeader->doff);
					break;
				}
				default:
				{
					LOG4CXX_TRACE(_logger, "TCP Header: "
							<< "Src Port:" << ntohs(tcpHeader->source)
							<< "\tDst Port:" << ntohs(tcpHeader->dest)
							<< "\tSeq=" << ntohl(tcpHeader->seq)
							<< "\tAckSeq=" << ntohl(tcpHeader->ack_seq)
							<< "\tWindow=" << ntohs(tcpHeader->window)
							<< "\tTCP Length=" << 4 * tcpHeader->doff);
				}
				}
				LOG4CXX_TRACE(_logger, "Invoking IP handler (TCP)");
#endif
				portDestination = ntohs(tcpHeader->dest);
			}
			else if(ipHeader->ip_p == IPPROTO_UDP)
			{
				struct udphdr *udpHeader;
				udpHeader = (struct udphdr *)packet;
#ifdef DEBUG
				if (ntohs(udpHeader->uh_dport) == PORT_DNS)
				{
					LOG4CXX_TRACE(_logger, "UDP Header: "
							<< "Src port:" << ntohs(udpHeader->source)
							<< " -> Dst port: " << ntohs(udpHeader->dest)
							<< " (DNS)");
				}
				else if (ntohs(udpHeader->uh_dport) == PORT_NETBIOS)
				{
					LOG4CXX_TRACE(_logger, "UDP Header: "
							<< "Src port:" << ntohs(udpHeader->source)
							<< " -> Dst port: " << ntohs(udpHeader->dest)
							<< " (NETBIOS)");
				}
				else if (ntohs(udpHeader->uh_dport) == PORT_COAP)
				{
					LOG4CXX_TRACE(_logger, "UDP Header: "
							<< "Src port:" << ntohs(udpHeader->source)
							<< " -> Dst port: " << ntohs(udpHeader->dest)
							<< " (CoAP)");
				}
				else
				{
					LOG4CXX_TRACE(_logger, "UDP Header: "
							<< "Src port:" << ntohs(udpHeader->source)
							<< " -> Dst port: " << ntohs(udpHeader->dest));
				}
				LOG4CXX_TRACE(_logger, "Invoking IP handler (UDP)");
#endif
				portDestination = ntohs(udpHeader->dest);
			}
			else if(ipHeader->ip_p == IPPROTO_ICMP)
			{
#ifdef DEBUG
				struct icmphdr *icmpHeader;
				icmpHeader = (struct icmphdr *)packet;
				LOG4CXX_TRACE(_logger, "ICMP Header: "
						<< "Code: " << ntohs(icmpHeader->code) << " | "
						<< "Type: " << ntohs(icmpHeader->type) << " | "
						<< "ID: " << ntohs(icmpHeader->un.echo.id) << " | "
						<< "Seq: " << ntohs(icmpHeader->un.echo.sequence)
						);
				LOG4CXX_TRACE(_logger, "Invoking IP handler (ICMP)");
#endif
				portDestination = PORT_ICMP;
			}
			else if (ipHeader->ip_p == IPPROTO_RAW)
			{
#ifdef DEBUG
				LOG4CXX_TRACE(_logger, "RAW IP packet received. "
						<< "No Layer 4 Header available");
				LOG4CXX_TRACE(_logger, "Invoking IP handler (RAW)");
#endif
				portDestination = PORT_UNKNOWN;
			}
			else
			{
#ifdef DEBUG
				LOG4CXX_DEBUG(_logger, "IP packet received with transport "
						<< "layer protocol " << ntohs(ipHeader->ip_p)
						<< " which has not been implemented. Falling back "
						<< "to default IP handler");
				LOG4CXX_TRACE(_logger, "Invoking IP handler");
#endif
				portDestination = PORT_UNKNOWN;
			}
			packet -= 4*ipHeader->ip_hl;
#ifdef DEBUG /* DEBUG start */
#ifdef TRACE /* TRACE start */
			IpHandler ipHandler(_nbBlackadder, _logger, _trace, srcIp,
					dstIp, portDestination, (PACKET *)packet,
					header->caplen - linkHdrLen,
					incomingPacketTimestamp, _db);
#else
			IpHandler ipHandler(_nbBlackadder, _logger, srcIp,
					dstIp, portDestination, (PACKET *)packet,
					header->caplen - linkHdrLen,
					incomingPacketTimestamp, _db);
#endif /* TRACE end */
#else /* DEBUG else */
#ifdef TRACE /* TRACE start */
			IpHandler ipHandler(_nbBlackadder, _trace, srcIp,
					dstIp, portDestination, (PACKET *)packet,
					header->caplen - linkHdrLen,
					incomingPacketTimestamp, _db);
#else
			IpHandler ipHandler(_nbBlackadder, srcIp, dstIp,
					portDestination, (PACKET *)packet,
					header->caplen - linkHdrLen,
					incomingPacketTimestamp, _db);
#endif /* TRACE end */
#endif /* DEBUG end */
			ipHandler();
			break;
		}
		// ARP packet inside Ethernet frame
		case ETHERTYPE_ARP:
		{
			packet += linkHdrLen;
#ifdef DEBUG
#ifdef TRACE
			ArpListener arpHandler(_nbBlackadder, _logger, _trace, _device, _db,
					packet,	incomingPacketTimestamp, _rawSocket);
#else
			ArpListener arpHandler(_nbBlackadder, _logger, _device, _db,
					packet,	incomingPacketTimestamp, _rawSocket);
#endif
#else
#ifdef TRACE
			ArpListener arpHandler(_nbBlackadder, _trace, _device, _db,
					packet,	incomingPacketTimestamp, _rawSocket);
#else
			ArpListener arpHandler(_nbBlackadder, _device, _db, packet,
					incomingPacketTimestamp, _rawSocket);
#endif
#endif
			arpHandler();
			break;
		}
		case ETHERTYPE_IPV6:
		{
#ifdef DEBUG
			LOG4CXX_TRACE(_logger, "IPv6 packets are not supported");
#endif
			break;
		}
		default:
		{
#ifdef DEBUG
			LOG4CXX_DEBUG(_logger, "Ethernet type " << ntohs(eptr->ether_type)
					<< " unknown, dropping packet");
#endif
		}
	}
}
void Demux::shutdown()
{
#ifdef DEBUG
	LOG4CXX_INFO(_logger, "Closing PCAP listener");
#endif
	pcap_close(_pcapHandler);
}
