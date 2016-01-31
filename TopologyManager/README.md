Blackadder API Library
**********************
The Topology Manager is a C++ ICN Pub/Sub application that communicates with Blackadder and other ICN applications
using the Pub/Sub service model provided by Blackadder user library in ../lib.

Dependencies
=================
- Blackadder
- libigraph0-dev
- libboost-dev

Installation and configuruation
=================
Refer to ../doc/HowTo.pdf

Running
=================
default:
sudo ./tm /tmp/topology.graphml

TE-extension:
sudo ./tm <EXT_OPTION> /tmp/topology.graphml

Extensions
=================
The Topology Manager Extensions are added functionalities to the core Topology manager that allows the TM to support Traffic Engineering solutions; each extension can be activated by using the corresponding flag, in similar way to the use of the deployment tool. These extensions include:

-	Traffic Engineering ( -t ):
    this extension allows the TM to provide multiple links for a single pub/sub request. This extension uses the boost graph library rather than igraph, therefore it is required to install libboost-dev.
-	Resiliency ( -r ) : 
    this extension allows the TM to support resiliency in the network. However, it should be noted that this will only allow the TM to support resiliency (it’s a one piece of the solution); to fully operate in a resiliency supported environment, run the Resilincy Manager as well (see the below secion)
-   QoS ( -q ):
    this extension allows the TM to provide QoS based path provisioning. Like resiliency, QoS activation in the Topology Manager is part of the solution. The other part is to configure the network links to support QoS.

Resiliency Manager
=================
The Resiliency Manager is a C++ ICN Pub/Sub application that communicates with Blackadder and the TM
using the Pub/Sub service model provided by Blackadder user library in ../lib.

To fully operate in a resilient network, it is required to activate/run the following:
Run the boradcast_linkstate_monitor: 
    to activate the failure detection mechanism, which will publish link failure alarms to the TM when a link is down,
    it is required to run the broadcast_linkstate_monitor application (in /examples/samples) in each blackadder node, or at least the nodes that supports resiliency. To run this application use:
    
    sudo ~/blackadder/examples/samples/broadcast_linkstate_monitor -i NodeID

Run the Resiliency Manager:
    Run the Resiliency Manager (named rm), which performs delivery failure detection and publish to the TM re-match pub/sub requests. To run this application:
    
        sudo ./rm /tmp/topology.graphml