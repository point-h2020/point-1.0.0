/*
 * Copyright (C) 2010-2016  George Parisis and Dirk Trossen
 * Copyright (C) 2015-2016  Mays AL-Naday
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

/**
 * @file blackadder_defs.h
 * @brief Blackadder definitions.
 */

#ifndef BLACKADDER_DEFS_HPP
#define BLACKADDER_DEFS_HPP

/**********************************/
#define PURSUIT_ID_LEN 8 //in bytes
#define FID_LEN 32 //in bytes
#define NODEID_LEN PURSUIT_ID_LEN //in bytes
/****some strategies*****/
#define LINK_LOCAL          1
#define DOMAIN_LOCAL        2
#define IMPLICIT_RENDEZVOUS 3
#define BROADCAST_IF        4
#define NODE_LOCAL          5
/************************/
/*intra and inter click message types*/
#define PUBLISH_SCOPE 0
#define PUBLISH_INFO 1
#define UNPUBLISH_SCOPE 2
#define UNPUBLISH_INFO 3
#define SUBSCRIBE_SCOPE 4
#define SUBSCRIBE_INFO 5
#define UNSUBSCRIBE_SCOPE 6
#define UNSUBSCRIBE_INFO 7
#define PUBLISH_DATA  8 //the request
#define PUBLISH_DATA_iSUB 9
#define CONNECT 12
#define DISCONNECT 13
#define ADD_LINK 14
#define REMOVE_LINK 15
#define DISCONNECTED 16
#define RECONNECTED 17
/*****************************/
#define UNDEF_EVENT 0
#define UPDATE_RVFID 55
#define UPDATE_TMFID 56
#define UPDATE_DELIVERY 57
#define DISCOVER_FAILURE 58
#define UPDATE_UNICAST_DELIVERY 59
#define START_PUBLISH 100
#define STOP_PUBLISH 101
#define SCOPE_PUBLISHED 102
#define SCOPE_UNPUBLISHED 103
#define PUBLISHED_DATA 104
#define MATCH_PUB_SUBS 105
#define RV_RESPONSE 106
#define UPDATE_FID 107
#define PUBLISHED_DATA_iSUB 108
#define MATCH_PUB_iSUBS 109
#define PUBLISH_DATA_iMULTICAST 110
#define UPDATE_FID_iSUB 111
#define RE_PUBLISH 112
#define PAUSE_PUBLISH 113
#define RESUME_PUBLISH 114
#define NETLINK_BADDER 30

#endif /* BLACKADDER_DEFS_HPP */
