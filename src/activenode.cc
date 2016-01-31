/*
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
#include "activenode.hh"

CLICK_DECLS

ActiveNode::ActiveNode(String _nodeID) {
    nodeID = _nodeID;
}

ActiveNode::~ActiveNode() {
}

CLICK_ENDDECLS
ELEMENT_PROVIDES(ActiveNode)