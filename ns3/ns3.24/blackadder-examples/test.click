require(blackadder);
globalconf::GlobalConf(MODE mac,NODEID 00000001,
DEFAULTRV 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,
iLID      1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,
TMFID     1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000);

localRV::LocalRV(globalconf,0);
toApps::ToSimDevice(tap0);
fromApps::FromSimDevice(tap0);
proxy::LocalProxy(globalconf);

fw::Forwarder(globalconf,0);

todev::ToSimDevice(eth0);
fromdev::FromSimDevice(eth0);



proxy[0] -> toApps;

fromApps-> [0]proxy;

localRV[0]->[1]proxy[1]->[0]localRV;

proxy[2]-> [0]fw[0] -> [2]proxy;

fw[1] -> Queue(1000) -> todev;
fromdev -> [1]fw;