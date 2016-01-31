# Introduction
The NAP module servers as the IP endpoint for devices and allows them to utilise POINT's ICN environment without any modification to the endpoint's communication stack. Any IP-based communication is natively supported. More information about the NAP and its current development status can be found on the POINT wiki: <http://wiki.point-h2020.eu/pointwiki/index.php?title=NAP>. 

The NAP support host-based as well as routing prefix-based set-ups which must be configured prior to the execution of the NAP binary. 

# Author
Sebastian Robitzsch <sebastian.robitzsch@interdigital.com>

# Compiliation
In order to install this software, simply invoke

$ make

in the nap directory. The required libraries are provided in the INSTALL text file which comes with this module, i.e.:

- libboost-program-options-dev (--help argument has been implemented using this library)
- libboost-thread-dev (creating threads)
- liblog4cxx10-dev (--debug argument has been implemente using this library)
- libpcap-dev (capture packets on local interface)
- libnet1-dev (send ARP and IP packets to IP end-points)

The complication optimisation level can be configured via the argument OPT, e.g.:

$ make OPT=O3

# How to Run and Configuration
For a complete list of arguments the NAP accepts please read the help first:

$ ./nap -h

Before starting the NAP binary, the ICN network (Blackadder, TM and RVZ) must be already running. The NAP uses a Blackadder instance on the machine it is invoked to send and receive ICN packets to and from Blackadder.

IMPORTANT: all IP endpoints connecting straight the NAP must set their MTU to 1400 bytes. Otherwise, Blackadder will not process the ICN packets due to a larger ICN header compared to Ethernet which causes packets of > 1500 bytes.

As mentioned before, the NAP is configured via a libconfig-based text file. The /doc directory comprises two example configuration files; one for the host-based set up and one for the data centre use case where routing prefixes are used. In order to not affect the git checkout it is highly recommended to first copy the required NAP configuration file from the /doc directory to its parent /nap folder.

$ cd /apps/nap
$ cp doc/nap-<DESIRED_SETUP>.cfg nap.cfg

When starting the NAP binary the configuration file must be provided using the -c or --configuration option:

$ sudo ./nap -c nap.cfg

The configuration file requires the following four entries:
- interface
- ipAddress
- netmask
- routingPrefix

The interface variable holds the local interface name, e.g., eth0 or wlan0, to which the NAP binds tos. This interface faces the IP endpoint(s) and must be configured accordingly. Note, this interface must not have any entry in iptables or ebtables which allows the kernel to route any incoming packet to another interface. For instance, assuming there's eth0 which provides Internet access and tap0 which is the VPN connection into the POINT testbed, there must be another interface, e.g., eth1, which faces the IP endpoint(s).

The ipAddress and netmask variables are used to tell the NAP which IP address (host-based) or IP address range (routing prefix) it is serving. The NAP uses this information to create the required scope (/NAMESPACE_IP/ROUTING_PREFIX_HASH/IP_ADDRESS/PORT).

The routingPrefix variable holds a list of all routing prefixes available inside the ICN network which are served by other NAPs. For services located in the Internet, the ICN GW (a NAP which has access to the Internet) can be reached by the last entry in both example configuration files, i.e., 0.0.0.0. A more detailed explanation what is understood by host-based and prefix-based environments can be found in the subsections below.

## Host-based Environment
The host-based environment is targeted at scenarios where the NAP is located at the customer's premises and a standard IP GW (home router) is provided by an ISP which performs some sort of address allocation (e.g., DHCP) and NAT. The NAP is connected to the outgoing IP GW's interface (IP: 86.89.101.206) which usually faces the ISP's network. In the host-based scenario the NAP is placed right behind the customer's home router. The router at the customer's premises believes to talk to the ISP's GW on 86.89.101.1 which happens to be the NAP:

UE		 |		 IP GW (home router)          | NAP
	 	 | private interface < NAT > public interface | 
192.168.0.x	 | 192.168.0.1/24    <     > 86.89.101.206    | 86.89.101.1


All UEs are connected to the home router and IP addresses are assigns manually or via DHCP. The IP GW performs NAT so that for all packets sent by UEs, the source address appear to be the public IP of the GW. For demonstration purposes it is assumed that the IP assignment of the router's public interface has been completed beforehand, e.g., via PPPoE. Finally, the NAP receives all packets from the IP GW with the GW's public IP address as the source address.

In order to advise the NAP that a host-based scenario is desired, the netmask variable in the configuration file must be set to 255.255.255.255. Any other mask would result in a routing prefix-based behaviour. Furthermore, the list of routing prefixes must comprise the corresponding routing prefix under which the ISP runs its network (e.g., 86.89.101.0/255.255.255.0). 

It is highly recommended to physically separate the three network elements UE, IP GW and the NAP. Initial attempts to use a tap interface for the NAP on a single machine (IP GW + NAP) resulted in issues with pcap and the ability capturing NATed packets on the virtual interface.

## Routing Prefix-based Environment
The routing prefix scenario represents a deployment where the NAP servers multiple IP endpoints, e.g., data centre gatways towards the Internet or a B-RAS at ISPs. In those environments several IP endpoints are accessible via a single machine (gateway, B-RAS) which accepts incoming packets based on routing prefixes.

The illustration below depicts an example where the NAP servers the routing prefix 64.62::/16 and is configured with a local IP of 64.62.0.1.

NAP	    /	Server1 (64.62.0.53)
64.62::/16 |	Server2 (64.62.5.3)
64.62.0.1   \	Server3 (64.62.32.76)

In the example configuration file (nap-prefix.cfg) the ipAddress and netmask variables represent the routing prefix of the IP endpoints the NAP should serve. When starting the NAP with this configuration a two-level scope is published /NAMESPACE_IP/ROUTING_PREFIX_HASH and the NAP subscribes to all scopes and information items advertised/published under this scope branch.

# Documentation
The NAP is entirely written in C++ and follows Doxygen syntax conventions to document the code. In order to generate the HTML files invoke

$ doxygen doxygen.conf

with the /doc directory which generates the HTML files within a dedicated folder. Make sure that graphviz has been installed beforehand:

$ apt install graphviz

# Debugging
## Logging Output to stdout
The NAP comes with five debugging levels which can be controlled using the -d or --debug argument when starting the NAP. The four debugging levels are:

 - FATAL: No such debugging message must appear. If it does, the NAP sub-component which threw the message stops working.
 - ERROR : No such debugging messages must appear. If it does, the NAP drops the information/packet it was handling and continues.
 - INFO : Only initialisation and bootstrapping information shown
 - DEBUG : Only newly added ICN IDs and published scopes are shown
 - TRACE : per packet trace information is printed from all NAP handler functions. This debugging option is NOT recommended in highly loaded networks

By default the debugging is set to FATAL.

## Trace Log to a File for Post-processing Purposes
From Version 1.2.0 onwards the NAP allows to write a packet traces to a file in the directory the NAP binary was executed. By using the argument --trace or -t a file named napTrace.tsv is generated (if already present, it is truncated) and all received and sent packets are written to it following NS-2 trace conventions. More information about what each value represents can be found in the Trace class documentation.

IMPORTANT: While in operation the trace file will be only truncated. All trace data is only written to internal output file stream in order to not slow down the NAP by writing to disk. Once the NAP is requested to terminate the deconstructor of the Trace class is called and the output file stream is written to the trace file. In other words, a $ tail -f napTrace.txt while the NAP is running won't show anything.
