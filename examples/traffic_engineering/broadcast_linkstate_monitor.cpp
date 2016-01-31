/*
 * Copyright (C) 2012-2016  Mays AL-Naday
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 3 as published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of
 * the BSD license.
 *
 * See LICENSE and COPYING for more details.
 */

#include <blackadder.hpp>
#include <nb_blackadder.hpp>
#include <bitvector.hpp>
#include <signal.h>
#include <map>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <getopt.h>

Blackadder *ba;

bool operation = true;
unsigned char net_type = 'e';
unsigned char update = ADD_LINK;
unsigned char state = RESUME_PUBLISH;
std::string nodeID;
std::string FID_str;
time_t live,last_lsu, lsu;
int notification_size = sizeof (update) + sizeof (net_type) + NODEID_LEN;
double lsu_diff;
double lifetime;
Bitvector *FID_to_TM;
std::map<string, time_t> connectivity;
std::map<string, time_t>::iterator con_itr;
pthread_t _event_listener, *event_listener = NULL;

std::string id;
std::string prefix_id = "0" + std::string(PURSUIT_ID_LEN*2-2, '1') + "0"; // "0111111111111110";
std::string bin_prefix_id = hex_to_chararray(prefix_id);

std::string resp_prefix_id = string(PURSUIT_ID_LEN*2-1, 'F') + "D"; // "FF..FFFFFFFFFFFFFD"
std::string bin_resp_prefix_id = hex_to_chararray(resp_prefix_id);

std::string lsn_prefix_id = string(PURSUIT_ID_LEN*2-1, 'F') + "A"; // "FF..FFFFFFFFFFFFFA"
std::string root_prefix_id = string();
std::string bin_lsn_prefix_id = hex_to_chararray(lsn_prefix_id);
std::string bin_root_prefix_id = hex_to_chararray(root_prefix_id);

std::string notification_id = string(PURSUIT_ID_LEN*2-1, 'F') + "8"; // "FF..FFFFFFFFFFFFFA"
std::string bin_notification_id = hex_to_chararray(notification_id);

using namespace std;


void sigfun(int sig) {
    (void) signal(SIGINT, SIG_DFL);
    operation=false;
    if (event_listener)
    pthread_cancel(*event_listener);
    ba->disconnect();
    delete ba;
    exit(0);
}
void *event_listener_loop(void *arg) {
    std::string full_id, rec_prefix_id, node_id;
    Blackadder *ba = (Blackadder *) arg;
    while(operation){
        Event ev;
        ba->getEvent(ev);
        switch (ev.type) {
                case PUBLISHED_DATA:
                full_id=chararray_to_hex(ev.id);
                node_id = std::string(ev.id, PURSUIT_ID_LEN, NODEID_LEN);
                rec_prefix_id=string (full_id, 0, PURSUIT_ID_LEN*2);
                if(ev.id==(resp_prefix_id + id)){
                    FID_to_TM = new Bitvector((char *)ev.data);
                    cout <<"Updated FID to TM: "<< FID_to_TM->to_string()<<endl;
                } else if(rec_prefix_id == prefix_id){
                    if ((connectivity.find(node_id)) == connectivity.end()) {
                        if (connectivity.begin() == connectivity.end()) {
                            update = RECONNECTED;
                            cout << "LSM: RECONNECTED" << endl;
                            char * notification = (char *)malloc(sizeof (update));
                            memcpy(notification, &update, sizeof(update));
                            ba->publish_data(bin_notification_id + id, NODE_LOCAL, NULL, 0, notification, sizeof (update));
                        }
                        connectivity.insert(pair<string, time_t>(node_id, time(&lsu)));
                        char * notification = (char *) malloc (notification_size);
                        update = ADD_LINK;
                        memcpy(notification, &update, sizeof (update));
                        memcpy(notification + sizeof (update), &net_type, sizeof (net_type));
                        memcpy(notification + sizeof (update) + sizeof (net_type), node_id.c_str(), NODEID_LEN);
                        cout << "LSM: FID_to_TM is: " << FID_to_TM->to_string()<<endl;
                        cout << "LSM: packet: " << chararray_to_hex(notification) << endl;
                        ba->publish_data(bin_lsn_prefix_id + id, IMPLICIT_RENDEZVOUS, (char *)FID_to_TM->_data, FID_LEN, notification, notification_size);
                        free(notification);
                    } else {
                        connectivity[node_id]= time(&lsu);
                    }
                    cout<<"NEIGHBOUR NODEID: "<<node_id<<endl;
                    break;
                }
                case PAUSE_PUBLISH:
                state = PAUSE_PUBLISH;
                break;
                case RESUME_PUBLISH:
                state = RESUME_PUBLISH;
                break;
        }
    }
    delete FID_to_TM;
    
    return NULL;
}

int main(int argc, char* argv[]) {
    (void) signal(SIGINT, sigfun);
    char c;
    int user_or_kernel = 0;
    lifetime = 5;
    string net_arg;
    while ((c = getopt (argc, argv, "nki:d:")) != -1){
        switch (c)
        {
                case 'n':
                net_arg = optarg;
                break;
                case 'k':
                user_or_kernel = 1;
                break;
                case 'i':
                nodeID = optarg;
                if (nodeID.length() - 1 < NODEID_LEN) {
                    id = string(NODEID_LEN - nodeID.length(), '0') + nodeID;
                } else {
                    id = nodeID;
                }
                break;
                case 'd':
                /*configure the lifetime to other value than the default 7 seconds*/
                lifetime = atof(optarg);
                cout << "Lifetime configured to be: " << lifetime << " seconds." << endl;
                break;
                case '?':
                if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
                return 1;
            default:
                cout << "LSM: something went wrong, aborting..." << endl;
                abort ();
        }
    }
    if (user_or_kernel == 0) {
        ba = Blackadder::Instance(true);
    } else {
        ba = Blackadder::Instance(false);
    }
    cout << "Process ID: " << getpid() << endl;
    if(id == ""){
        cout<<"Please Enter your NodeID: "<<endl;
        getline(cin, id);
    }
    int advertisement_size=sizeof(time_t);
    char *advertisement = (char *) malloc(advertisement_size);
    std::string id_to_broadcast = bin_prefix_id + id;
    time_t countt;
    countt=time(& countt);
    std::string dis_node;
    ifstream getfid;
    std::string file_name = "/tmp/";
    file_name+=id;
    file_name+="_TMFID.txt";
    getfid.open(file_name.c_str());
    if (getfid.is_open()){
        getline(getfid, FID_str);
    }
    FID_to_TM = new Bitvector(FID_str);
    cout<<"Net type is: "<< net_type << endl << "Initial FID_to_TM is:" << FID_to_TM->to_string()<<endl;
    pthread_create(&_event_listener, NULL, event_listener_loop, (void *) ba);
    event_listener = &_event_listener;
    ba->subscribe_scope(bin_prefix_id, bin_root_prefix_id, BROADCAST_IF, NULL, 0);
    while(operation) {
        sleep(1);
        time(&live);
        advertisement= ctime(&countt);
        if (update != DISCONNECTED) {
            ba->publish_data(id_to_broadcast, BROADCAST_IF, NULL, 0, advertisement, advertisement_size);
            time(&countt);
            cout << "Not disconnected" << endl;
            for(con_itr=connectivity.begin(); con_itr!=connectivity.end();){
                last_lsu = (*con_itr).second;
                lsu_diff = difftime(live, last_lsu);
                printf("difference is : %.2lf\n", lsu_diff);
                if (lsu_diff > lifetime) {
                    dis_node=std::string((*con_itr).first);
                    connectivity.erase(con_itr++);
                    char * notification = (char *) malloc (notification_size);
                    update = REMOVE_LINK;
                    memcpy(notification, &update, sizeof (update));
                    memcpy(notification + sizeof (update), &net_type, sizeof (net_type));
                    memcpy(notification + sizeof (update) + sizeof (net_type), (char *)dis_node.c_str(), NODEID_LEN);
                    ba->publish_data(bin_lsn_prefix_id + id, IMPLICIT_RENDEZVOUS,(char *)FID_to_TM->_data, FID_LEN, notification, notification_size);
                    if (connectivity.size() == 0) {
                        update = DISCONNECTED;
                    }
                    free(notification);
                } else {
                    con_itr++;
                }
            }
        } else if ((update == DISCONNECTED) && (state != PAUSE_PUBLISH)){
            cout << "LSM: Disconnected..."<< endl;
            char * notification = (char *)malloc(sizeof (update));
            memcpy(notification, &update, sizeof(update));
            ba->publish_data(bin_notification_id + id, NODE_LOCAL, NULL, 0, notification, sizeof(update));
        }
    }
    pthread_join(*event_listener, NULL);
    free(advertisement);
    return 0;
}
