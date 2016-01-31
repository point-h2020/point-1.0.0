Introduction
=============================

This is the development version of the POINT platform.
Currently published as POINT Cycle-1 release.
This document  outlines the modules that comprises the POINT platform, including their objectives and operation.
It is recommend that the reader refer to the POINT D3.1 “First Platform Design”  and D3.2 “Cycle1 Platform Implementation Documentation”  For comprehensive understanding of the POINT platform.

For details on how to install and configure the platform, see to the HowTo document in ~/blackadder/doc/

For Hands-on example scenarios of testing ICN setups, see to the Examples document in ~/blackadder/doc/

See also: https://github.com/fp7-pursuit/blackadder

If you use this work for a publication it would be good if you could
cite the following publication:

@inproceedings{DBLP:conf/networking/ParisisTS13,
author    = {George Parisis and
Dirk Trossen and
Dimitris Syrivelis},
title     = {Implementation and evaluation of an information-centric network},
booktitle = {{IFIP} Networking Conference, 2013, Brooklyn, New York, USA, 22-24
May, 2013},
pages     = {1--9},
year      = {2013},
crossref  = {DBLP:conf/networking/2013},
url       = {http://ieeexplore.ieee.org/xpl/articleDetails.jsp?arnumber=6663525},
timestamp = {Sat, 01 Feb 2014 15:37:20 +0100},
biburl    = {http://dblp.uni-trier.de/rec/bib/conf/networking/ParisisTS13},
bibsource = {dblp computer science bibliography, http://dblp.org}
}

Modules
=============================

The deployment Tool:
=============================

The deployment utility is an external tool that reads a configuration file, the syntax of which is described in the HowTo, and produces Click configuration files for all nodes in an ICN network. The deployment tool also has an extension that supports dynamic addition/deletion of nodes from the deployable topology. For further details about the deployment tool, please refer to the README.md  in ~/blackadder/deployment/

Blackadder:
=============================

Blackadder is a Click-based implementation of the core ICN node in the POINT platform, providing the Rendezvous (RV) and Forwarding (FW) functions as click elements, in addition to the main process dispatcher (LocalProxy) and the global ICN configuration element (GlobalConf). Inter-process communication is facilitated between the elements, using netlink sockets, to allow for message exchange among the elements of Blackadder as well as packet forwarding between ICN applications across the network. Blackadder currently supports both native ICN and IP-over-ICN  communications. Blackadder source code is placed in ~/blackadder/src. For further details about Blackadder, refer to the README.md in ~/blackadder/src/.

Blackadder User Library:
=============================

Blackadder user library is a C++ application that exposes an ICN Pub/Sub service model to the ICN applications, through netlink-based inter-process communication, allowing them to interact with Blackadder and with remote ICN applications across the ICN network. Currently, the user library provides both blocking and non-blocking API. The source code of the library can be found in ~/blackadder/lib. For further details about the library, refer to the README.md in ~/blackadder/lib/.

ICN Applications
=============================
Topology Manager:
=============================
The TM is an ICN Pub/Sub application that communicates with the RV and with other ICN applications over predefined set of control scopes. The TM provides basic path calculation based on Shortest Path algorithm, as well as a set of Traffic Engineering (TE) extensions aimed at supporting load-balance, resiliency/path management and QoS.
Currently, the TM provides path calculation for ICN and IP-over-ICN communications. All the TM extensions are provided for native ICN communications, while only resiliency through the Resiliency Manager is provided for IP-over-ICN. Future releases will support more of the TM extensions for IP-over-ICN. The TM source code can be found in ~/blackadder/TopologyManager. For further details, refer to the README.md in ~/blackadder/TopologyManager/.

Resiliency Manager:
=============================

The RM is an ICN Pub/Sub application that communicates with the TM extension of resiliency over a predefined set of control scopes, to maintain state of delivery paths/trees in the network and request a delivery recalculation in case of network changes (e.g. failure). The RM currently supports both ICN and IP-over-ICN communications. The RM source code is in the same directory as the TM. For further details, refer to the README.md in ~/blackadder/TopologyManager/.

Network Attachment Point:
=============================

The NAP is an ICN Pub/Sub application that acts as a gateway connecting an IP network to an ICN. The NAP maps the IP address of IP packets to the appropriate namespace in the ICN network, which it then publish/subscribe on behalf of the IP end-point. Currently the NAP supports two operation scenarios: host and route prefix. The host scenarios is aimed at supporting a home gateway setup; whilst the route prefix aimed at supporting a data centre network. The NAP communicates with Blackadder and the TM through the service model provided by Blackadder user library. The NAP source code can be found in ~/blackadder/apps/nap. For further details about the NAP, refer to the README.md in ~/blackadder/apps/nap/.

NS3
=============================

Refer to the NS3HowTo for details of NS3-Blackadder integration.