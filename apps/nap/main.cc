/**
 * main.cc
 *
 * Created on 19 April 2015
 * 		Author: Sebastian Robitzsch <sebastian.robitzsch@interdigital.com>
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
#include <libconfig.h++>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/logger.h>
#include <log4cxx/simplelayout.h>
#include <net/ethernet.h>
#include <signal.h>
#include <stdlib.h>
#include <string>
#include "buffercleaner.hh"
#include "demux.hh"
#include "handlers/icnhandler.hh"
#include "helper.hh"
#include "socket.hh"
#include "typedef.hh"
using namespace libconfig;
namespace po = boost::program_options;
using namespace std;
// A helper log4cxx function to simplify the main part.
template<class T>
ostream& operator<<(ostream& os, const vector<T>& v)
{
    copy(v.begin(), v.end(), ostream_iterator<T>(os, " "));
    return os;
}
#ifdef DEBUG
log4cxx::ConsoleAppender * consoleAppender =
		new log4cxx::ConsoleAppender(log4cxx::LayoutPtr(new log4cxx::SimpleLayout()));
log4cxx::LoggerPtr logger = log4cxx::Logger::getLogger("logger");
#endif
NB_Blackadder *nbBlackadder;
#ifdef DEBUG
Database database(logger);
#else
Database database;
#endif
#ifdef TRACE
Trace trace;
#endif
#ifdef DEBUG /* DEBUG start*/
#ifdef TRACE /* TRACE start */
Socket rawSocket(database, logger, trace);
#else
Socket rawSocket(database, logger);
#endif /* TRACE end */
#else
#ifdef TRACE /* TRACE start */
Socket rawSocket(database, trace);
#else
Socket rawSocket(database);
#endif /* TRACE end */
#endif /* DEBUG end*/
/*!
 * \brief ICN callback function
 *
 * This function is called by Blackadder every time it has received an ICN
 * packet destined for this NAP.
 *
 * \param ev Pointer to the ICN event
 */
void callback(Event *ev);
/*!
 * \brief Capturing user interactions
 *
 * This function is called once the user issues Ctrl+C
 *
 * \param sig The signal captured
 */
void sigfun(int sig) {
#ifdef DEBUG
	LOG4CXX_INFO(logger, "NAP termination requested");
#endif
	database.runNap = false;
    (void) signal(sig, SIG_DFL);
}

int main(int ac, char* av[]) {
	bool baUserSpace;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if *listOfInterfaces,
			*intDescr;
	//boost::thread_group threads;
#ifdef DEBUG
	log4cxx::BasicConfigurator::configure(log4cxx::AppenderPtr(consoleAppender));
#endif
	string device;
	try {
		po::options_description desc("Network Attachment Point (NAP) module for POINT testbed\nAuthor:\t Sebastian Robitzsch <sebastian.robitzsch@interdigital.com>\n\nAllowed options");
		desc.add_options()
		("configuration,c", po::value< string >(), "libconfig-based configuration file for NAP")
#ifdef DEBUG
		("debug,d", po::value< string >(), "Enable verbosity (ERROR|INFO|DEBUG|TRACE)")
		("file,f", "Write the debugging output requested using argument '--debug' to /tmp/nap.log")
#endif
		("help,h", "Print this help message")
		("kernel,k", "Tell NAP that Blackadder runs in kernel space")
#ifdef TRACE
		("trace,t", "Write incoming and outgoing packet traces to /tmp/napTrace.tsv")
		("tracepath,r", po::value< string >(), "Changing directory for trace file napTrace.tsv")
#endif
		("version,v", "Print the version number of this software.")
		;
		po::positional_options_description p;
		po::variables_map vm;
		po::store(
				po::command_line_parser(ac, av).options(desc).positional(p).run(),
				vm);
		po::notify(vm);
		if (vm.count("help")) {
			cout << desc;
			return EXIT_SUCCESS;
		}
		if (vm.count("version"))
		{
			cout << "This NAP runs version 1.4.6\n";
			return 0;
		}
#ifdef DEBUG
		// Reading verbose level
		if (vm.count("debug"))
		{
			if (vm["debug"].as< string >() == "FATAL")
			{
				log4cxx::Logger::getRootLogger()->setLevel(
						log4cxx::Level::getFatal());
				LOG4CXX_ERROR(logger,"Verbose level set to FATAL");
			}
			else if (vm["debug"].as< string >() == "ERROR")
			{
				log4cxx::Logger::getRootLogger()->setLevel(
						log4cxx::Level::getError());
				LOG4CXX_ERROR(logger,"Verbose level set to ERROR");
			}
			else if (vm["debug"].as< string >() == "INFO")
			{
				log4cxx::Logger::getRootLogger()->setLevel(
						log4cxx::Level::getInfo());
				LOG4CXX_INFO(logger,"Verbose level set to INFO");
			}
			else if (vm["debug"].as< string >() == "DEBUG")
			{
				log4cxx::Logger::getRootLogger()->setLevel(
						log4cxx::Level::getDebug());
				LOG4CXX_DEBUG(logger,"Verbose level set to DEBUG");
			}
			else if (vm["debug"].as< string >() == "TRACE")
			{
				log4cxx::Logger::getRootLogger()->setLevel(
						log4cxx::Level::getTrace());
				LOG4CXX_TRACE(logger,"Verbose level set to TRACE");
			}
			else
			{
				LOG4CXX_ERROR(logger, "Unknown debug mode");
				return EXIT_FAILURE;
			}
		}
		else
			log4cxx::Logger::getRootLogger()->setLevel(
					log4cxx::Level::getFatal());

		// Reading if NAP should write debugging output to file too
		if (vm.count("debug") && vm.count("file"))
		{
			log4cxx::FileAppender * fileAppender =
					new log4cxx::FileAppender(log4cxx::LayoutPtr(
							new log4cxx::SimpleLayout()), "/tmp/nap.log", false);
			log4cxx::helpers::Pool p;
			log4cxx::BasicConfigurator::configure(
					log4cxx::AppenderPtr(fileAppender));
			fileAppender->activateOptions(p);
		}
#endif
		// Reading whether Blackadder runs in user or kernel space
		if (vm.count("kernel"))
			baUserSpace = false;
		else
			baUserSpace = true;
#ifdef TRACE
		if (vm.count("trace"))
		{
			trace.enableTracing();
			if (vm.count("tracepath"))
			{
				trace.changeTraceFilePath(vm["tracepath"].as< string >());
#ifdef DEBUG
				LOG4CXX_INFO(logger, "Writing packet trace to file "
						<< vm["tracepath"].as< string >() << "/napTrace.tsv");
#endif
			}
#ifdef DEBUG
			else
				LOG4CXX_INFO(logger,
						"Writing packet trace to file '/tmp/napTrace.tsv'");
#endif
		}
#endif
		if (getuid() != 0)
		{
#ifdef DEBUG
			if (logger->getEffectiveLevel()->toInt() > ERROR_INT)
				cout << "The NAP must run with root (sudo) privileges\n";

			else
				LOG4CXX_ERROR(logger, "The NAP must run with root (sudo) privileges");
#endif
			return EXIT_FAILURE;
		}
		// Instantiate Blackadder
		nbBlackadder = NB_Blackadder::Instance(baUserSpace);
		nbBlackadder->setCallback(callback);
		// Reading NAP config
		if (vm.count("configuration"))
		{
			Config cfg;
			try
			{
				cfg.readFile(vm["configuration"].as< string >().c_str());
			}
			catch(const FileIOException &fioex)
			{
#ifdef DEBUG
				LOG4CXX_ERROR(logger,"Cannot read "
						<< vm["configuration"].as< string >());
#endif
				return EXIT_FAILURE;
			}
			catch(const ParseException &pex)
			{
#ifdef DEBUG
				LOG4CXX_ERROR(logger, "Parse error in file "
						<< vm["configuration"].as< string >());
#endif
				return EXIT_FAILURE;
			}
			// Reading root
			const Setting& root = cfg.getRoot();
			try
			{
				Helper helper;
				string ip, mask, nodeId;
				struct in_addr address;
#ifdef DEBUG
				LOG4CXX_INFO(logger, "Reading libconfig-based NAP configuration"
						<< " file " << vm["configuration"].as< string >());
#endif
				const Setting &napConfig = root["napConfig"];
				if (!napConfig.lookupValue("interface", device))
				{
#ifdef DEBUG
					LOG4CXX_FATAL(logger, "'interface' could not be read");
#endif
					return EXIT_FAILURE;
				}
				if (!napConfig.lookupValue("networkAddress", ip))
				{
#ifdef DEBUG
					LOG4CXX_FATAL(logger, "'networkAddress' could not be read");
#endif
					return EXIT_FAILURE;
				}
				if(!napConfig.lookupValue("netmask", mask))
				{
#ifdef DEBUG
					LOG4CXX_FATAL(logger, "'netmask' could not be read");
#endif
					return EXIT_FAILURE;
				}
				inet_aton(ip.c_str(), &address);
				database.hostNetworkAddress = address.s_addr;
				inet_aton(mask.c_str(), &address);
				database.hostNetmask = address.s_addr;
				database.hostRoutingPrefix.networkAddress = database.hostNetworkAddress;
				database.hostRoutingPrefix.netmask = database.hostNetmask;
				database.hostRoutingPrefix.appliedMask =
						database.hostNetworkAddress & database.hostNetmask;
				// Ignore host-based and ICN GW scenarios
				if (mask.compare("255.255.255.255") != 0
						&& mask.compare("0.0.0.0") != 0)
				{
					database.addRoutingPrefix(database.hostRoutingPrefix);
				}
#ifdef DEBUG
				else
				{
					LOG4CXX_DEBUG(logger, "Ignoring IP and netmask setting "
							<< helper.printRoutingPrefix(
									database.hostRoutingPrefix) << " for this "
							<< "NAP. This will not be added to list of routing"
							<< " prefixes available in the ICN network");
				}
#endif
				if (mask.compare("0.0.0.0") == 0)
				{// I'm the ICN GW
#ifdef DEBUG
					LOG4CXX_INFO(logger, "This NAP acts as an ICN GW");
#endif
					database.icnGateway = true;
				}
				int threadPriority;
				if (napConfig.lookupValue("threadPriority", threadPriority))
				{
					database.threadPriority = threadPriority;
#ifdef DEBUG
					LOG4CXX_INFO(logger, "'threadPriority' set to "
							<< threadPriority);
#endif
				}
			}
			catch(const SettingNotFoundException &nfex)
			{
#ifdef DEBUG
					LOG4CXX_FATAL(logger, "Setting not found in "
							<< vm["configuration"].as< string >());
#endif
					return false;
			}
			// Reading routing prefixes
			const Setting& routingPrefixes =
					root["napConfig"]["routingPrefixes"];
			try{
				size_t count = routingPrefixes.getLength();
				for (size_t i = 0; i < count; i++)
				{
					string ip, mask;
					struct in_addr ipAddress, netmask;
					ROUTING_PREFIX prefix;
					ICN_ID icnId;
					Helper helper;
					HASH_STR hash;
					ostringstream oss, am;
					const Setting &routingPrefix = routingPrefixes[i];
					if (!(routingPrefix.lookupValue("networkAddress", ip)))
					{
#ifdef DEBUG
						LOG4CXX_FATAL(logger, "Network address of a routing "
								<< "prefix could not be read");
#endif
						return EXIT_FAILURE;
					}
					if (!(routingPrefix.lookupValue("netmask", mask)))
					{
#ifdef DEBUG
						LOG4CXX_FATAL(logger, "Netmask of a routing prefix "
								<< "could not be read");
#endif
						return EXIT_FAILURE;
					}
					inet_aton(ip.c_str(), &ipAddress);
					prefix.networkAddress= ipAddress.s_addr;
					inet_aton(mask.c_str(), &netmask);
					prefix.netmask = netmask.s_addr;
					prefix.appliedMask = ipAddress.s_addr & netmask.s_addr;
					am << prefix.appliedMask;
					oss << hash(am.str());
					if (oss.str().length() > ID_LEN)
					{
						prefix.hashedPrefix = prefix.appliedMask;
					}
					else
					{
						prefix.hashedPrefix = hash(am.str());
					}
					database.addRoutingPrefix(prefix);
				}
			}
			catch(const SettingNotFoundException &nfex)
			{
#ifdef DEBUG
				LOG4CXX_FATAL(logger, "Routing prefixes could not be read "
						<< "from " << vm["configuration"].as< string >());
#endif
				return false;
			}
			// Reading FQDN Registrations
			const Setting &fqdns = root["napConfig"]["fqdns"];
			IP_ADDRESS ipAddress;
			struct in_addr ipAddr;
			string id, prefixId;
			ICN_ID icnId;
			Helper helper;
			size_t count = fqdns.getLength();
			for (size_t i = 0; i < count; i++)
			{
				string ip, fqdn;
				const Setting &f = fqdns[i];
				if (!(f.lookupValue("fqdn", fqdn)))
				{
#ifdef DEBUG
					LOG4CXX_FATAL(logger, "FQDN could not be read");
#endif
					return EXIT_FAILURE;
				}
				if (!(f.lookupValue("ipAddress", ip)))
				{
#ifdef DEBUG
					LOG4CXX_FATAL(logger, "IP address for FQDN registration"
							<< " could not be read");
#endif
					return EXIT_FAILURE;
				}
				inet_aton(ip.c_str(), &ipAddr);
				ipAddress = ipAddr.s_addr;
				icnId = helper.toIcnId(NAMESPACE_HTTP, fqdn);
				database.addIcnId(icnId, fqdn, ipAddress);
				// Creating HTTP root scope and publish FQDN
				id = helper.getScopeId(icnId, SCOPE_LEVEL_HTTP_ROOT);
				prefixId = string();
#ifdef DEBUG
				LOG4CXX_DEBUG(logger, "Publish HTTP root scope </" << id
						<< ">");
#endif
				nbBlackadder->publish_scope(hex_to_chararray(id),
						hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL, 0);
				prefixId = id;
				id = helper.getScopeId(icnId, SCOPE_LEVEL_HTTP_FQDN);
				if (id.size() > ID_LEN)
				{
#ifdef DEBUG
					LOG4CXX_DEBUG(logger, "Chunk the hashed FQDN iItem "
							<< fqdn << " into: " << helper.printIcnId(id));
#endif
					for (size_t chunk = 0;
							chunk < (id.size() / ID_LEN); chunk++)
					{
						ostringstream oss;
						for (size_t it = 0; it < ID_LEN; it++)
						{
							oss << id[chunk * ID_LEN + it];
						}
						if (chunk != (id.size() / ID_LEN - 1))
						{
#ifdef DEBUG
							LOG4CXX_DEBUG(logger, "Publish FQDN scope "
									<< helper.printIcnId(oss.str())
									<< " under HTTP father scope "
									<< helper.printIcnId(prefixId));
#endif
							nbBlackadder->publish_scope(
									hex_to_chararray(oss.str()),
									hex_to_chararray(prefixId), DOMAIN_LOCAL,
									NULL, 0);
						}
						else
						{
#ifdef DEBUG
							LOG4CXX_DEBUG(logger, "Subscribe to FQDN iItem "
									<< helper.printIcnId(oss.str())
									<< " under HTTP father scope "
									<< helper.printIcnId(prefixId));
#endif
							nbBlackadder->subscribe_info(
									hex_to_chararray(oss.str()),
									hex_to_chararray(prefixId), DOMAIN_LOCAL,
									NULL, 0);
						}
						prefixId.append(oss.str());
					}
				}
				else
				{
					nbBlackadder->subscribe_info(hex_to_chararray(id),
							hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL,
							0);

				}
				database.setScopePublicationStatus(icnId, true);
			}
		}
		else
		{
			cout << "NAP libconfig-based configuration file has not been "
					<< "provided via option --configuration or -c\n";
			return EXIT_FAILURE;
		}
		// Get local ICN ID and subscribe to all scopes used to publish beneth
		struct in_addr address;
		inet_aton("255.255.255.255", &address);
		// Host-based
		if (database.hostNetmask == address.s_addr)
		{
			Helper helper;
			ROUTING_PREFIX prefix;
			ICN_ID icnId;
			if (!database.getRoutingPrefix(database.hostNetworkAddress, prefix))
			{
#ifdef DEBUG
				LOG4CXX_FATAL(logger, "Host IP doesn't match with any provided "
						<< "prefixes. Check your configuration file");
#endif
				return EXIT_FAILURE;
			}
			icnId = helper.toIcnId(prefix, database.hostNetworkAddress,
					PORT_UNKNOWN);
			database.addIcnId(icnId, database.hostNetworkAddress, PORT_UNKNOWN,
					true);
			database.hostRoutingPrefix = prefix;
		}
		// Prefix-based (database.hostRoutingPrefix has been already written)
		else
		{
			Helper helper;
			ICN_ID icnId = helper.toIcnId(database.hostRoutingPrefix,
					database.hostRoutingPrefix.networkAddress, PORT_UNKNOWN);
			database.addIcnId(icnId, database.hostRoutingPrefix.networkAddress,
					PORT_UNKNOWN, true);
		}
		if (pcap_findalldevs(&listOfInterfaces, errbuf) < 0)
		{
#ifdef DEBUG
			LOG4CXX_FATAL(logger, "No local interfaces available");
#endif
			return EXIT_FAILURE;
		}
		// Obtaining all local interfaces and start listener threads
		bool deviceFound = false;
		EUI48 macAddress;
		for (intDescr = listOfInterfaces; intDescr; intDescr = intDescr->next)
		{
			Helper helper;
			int sock;
			struct ifreq ifr, ifreqMac;
			char MAC_str[13];
			ostringstream oss;
			IP_ADDRESS ipAddress;
			sock = socket(AF_INET, SOCK_DGRAM, 0);
			ifr.ifr_addr.sa_family = AF_INET;
			strncpy(ifr.ifr_name, intDescr->name, IFNAMSIZ-1);
			ioctl(sock, SIOCGIFADDR, &ifr);
			close(sock);
			if (strcmp(intDescr->name, device.c_str()) == 0)
			{
#ifdef DEBUG
				LOG4CXX_DEBUG(logger, "Local interface " << device << " found");
#endif
				deviceFound = true;
				sock = socket(AF_INET, SOCK_DGRAM, 0);
				strcpy(ifreqMac.ifr_name, intDescr->name);
				ioctl(sock, SIOCGIFHWADDR, &ifreqMac);
				for (int i=0; i<6; i++)
				{
					sprintf(&MAC_str[i*2],"%02X",
							((unsigned char*)ifreqMac.ifr_hwaddr.sa_data)[i]);
				}
				MAC_str[12]='\0';
				oss << MAC_str;
				macAddress = oss.str();
				ipAddress =
						((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
				// read MTU (and change if required)
				if((ioctl(sock, SIOCGIFMTU, &ifr)) == -1){
#ifdef DEBUG /* DEBUG start */
					LOG4CXX_ERROR(logger, "MTU could not be read. Assuming it "
							<< "is set to 1500 bytes");
#endif /* DEBUG end */
				}
				close(sock);
				if (ifr.ifr_mtu < database.getIpMtu())
				{
					database.setIpMtu(ifr.ifr_mtu);
#ifdef DEBUG /* DEBUG start */
					LOG4CXX_INFO(logger, "MTU for NAP interface "
						<< intDescr->name << " changed to "
						<< database.getIpMtu() << " bytes");
#endif /* DEBUG end */
				}
				database.hostIpAddressDevice = ipAddress;
				database.addIpEui48Pair(database.hostIpAddressDevice, macAddress);
				rawSocket.createSocket(intDescr->name);
#ifdef DEBUG /* DEBUG start */
#ifdef TRACE /* TRACE start */
				Demux demux(nbBlackadder, logger, trace, intDescr->name,
						database, rawSocket);
#else
				Demux demux(nbBlackadder, logger, intDescr->name, database,
						rawSocket);
#endif /* TRACE end */
#else
#ifdef TRACE
				Demux demux(nbBlackadder, trace, intDescr->name, database,
						rawSocket);
#else
				Demux demux(nbBlackadder, intDescr->name, database, rawSocket);
#endif /* TRACE end */
#endif /* DEBUG end */
				//threads.create_thread(demux);
				boost::thread demuxThread(demux);
				if (database.threadPriority != 0)
					demux.changeSchedulerParameters(demuxThread);
			}
		}
		if (deviceFound == false)
		{
#ifdef DEBUG
			LOG4CXX_FATAL(logger,"Networking interface " << device
					<< " not found. Exiting.");
#endif
			//threads.interrupt_all();
			return EXIT_FAILURE;
		}
		// Start buffer cleaner thread
#ifdef DEBUG
		LOG4CXX_INFO(logger, "Starting buffer cleaner");
#endif
		BufferCleaner bufferCleaner(database);
		//threads.create_thread(bufferCleaner);
		boost::thread bufferCleanerThread(bufferCleaner);
		// Start proxy listener
		/*
#ifdef DEBUG
		LOG4CXX_INFO(logger, "Starting proxy listener");
#ifdef TRACE
		ProxyListener proxyListener(nbBlackadder, logger, trace, database);
#else
		ProxyListener proxyListener(nbBlackadder, logger, database);
#endif
#else
#ifdef TRACE
		ProxyListener proxyListener(nbBlackadder, trace, database);
#else
		ProxyListener proxyListener(nbBlackadder, database);
#endif
#endif
		boost::thread proxyListenerThread(proxyListener);
		*/
		while (database.runNap)
		{
			(void) signal(SIGINT, sigfun);
			sleep(1);
		}
#ifdef TRACE
		trace.closeTraceFile();
#endif
		// unpublish all scope branches this NAP created
		Helper helper;
		string id, prefixId;
		ICN_ID icnId = helper.toIcnId(database.hostRoutingPrefix,
				database.hostNetworkAddress, PORT_UNKNOWN);
		// host-based deployment
		if (database.hostNetworkAddress !=
				database.hostRoutingPrefix.networkAddress)
		{
			id = helper.getScopeId(icnId, SCOPE_LEVEL_IP_IPADDRESS);
			prefixId = helper.getScopePath(icnId, SCOPE_LEVEL_IP_PREFIX);
			nbBlackadder->unpublish_info(hex_to_chararray(id),
				hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL,	0);
#ifdef DEBUG
			LOG4CXX_DEBUG(logger, "Unsubscribe from items under scope "
					<< helper.printScopePath(icnId, SCOPE_LEVEL_IP_IPADDRESS));
#endif
			nbBlackadder->unpublish_scope(hex_to_chararray(id),
				hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL,	0);
#ifdef DEBUG
			LOG4CXX_DEBUG(logger, "Unpublish scope <" << id
					<< "> under father scope "
					<< helper.printScopePath(icnId, SCOPE_LEVEL_IP_PREFIX));
#endif
		}
		// routing prefix-based deployment
		else
		{
			id = helper.getScopeId(icnId, SCOPE_LEVEL_IP_PREFIX);
			prefixId = helper.getScopePath(icnId, SCOPE_LEVEL_IP_ROOT);
			nbBlackadder->unsubscribe_scope(hex_to_chararray(id),
					hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL,	0);
#ifdef DEBUG
			LOG4CXX_DEBUG(logger,"Unsubscribe from scope path "
					<< helper.printScopePath(icnId, SCOPE_LEVEL_IP_PREFIX));
#endif
		}
		// Unpublish prefix scope under root scope
		id = helper.getScopeId(icnId, SCOPE_LEVEL_IP_PREFIX);
		prefixId = helper.getScopePath(icnId, SCOPE_LEVEL_IP_ROOT);
		nbBlackadder->unpublish_scope(hex_to_chararray(id),
				hex_to_chararray(prefixId), DOMAIN_LOCAL, NULL,	0);
#ifdef DEBUG
		LOG4CXX_DEBUG(logger, "Unpublish scope <" << id	<< "> under father scope "
				<< helper.printScopePath(icnId, SCOPE_LEVEL_IP_ROOT));
#endif
		sleep(1);// give BA some time to process unsubscribe msgs
#ifdef DEBUG
		LOG4CXX_DEBUG(logger, "Disconnecting from Blackadder");
#endif
		nbBlackadder->disconnect();
		delete nbBlackadder;
		pcap_freealldevs(listOfInterfaces);
		//LOG4CXX_DEBUG(logger, "Interrupting all threads");
		//threads.interrupt_all();
#ifdef DEBUG
		LOG4CXX_DEBUG(logger, "Exiting ... bye, bye");
#endif
		return EXIT_SUCCESS;
	}
	catch(std::exception& e)
	{
		cout << e.what() << "\n";
		return EXIT_FAILURE;
	}
}

void callback(Event *ev)
{
#ifdef DEBUG /* DEBUG start */
#ifdef TRACE /* TRACE start */
	IcnHandler icnHandler(nbBlackadder, logger, trace, ev, database, rawSocket);
#else
	IcnHandler icnHandler(nbBlackadder, logger, ev, database, rawSocket);
#endif /* TRACE end */
#else
#ifdef TRACE /* TRACE start */
	IcnHandler icnHandler(nbBlackadder, trace, ev, database, rawSocket);
#else
	IcnHandler icnHandler(nbBlackadder, ev, database, rawSocket);
#endif /* TRACE end */
#endif /* DEBUG end */
	icnHandler();
	delete ev;
}
