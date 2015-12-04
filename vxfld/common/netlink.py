# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2015 Cumulus Networks, Inc. All rights reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.
# 51 Franklin Street, Fifth Floor
# Boston, MA  02110-1301, USA.
""" This module contains classes that provide methods to handle netlink
notifications.
"""
import collections
import os
import socket
import sys

import eventlet
import greenlet

from vxfld.common.netlink_decoder import (Decoder,
                                          DecodeError,
                                          Ifla,
                                          IflaLinkInfo,
                                          IflaVxlan,
                                          RtnlGroupType,
                                          RtnlMsgType)


class VxlanDevice(object):
    """ Stores Vxlan device related information.
    """
    # pylint: disable=too-few-public-methods,too-many-arguments
    def __init__(self, ifindex, dev_name, state, vni, local, dstport=None,
                 remote=None):
        self.dev_name = dev_name
        self.dstport = dstport
        self.ifindex = ifindex
        self.localip = local
        self.remoteip = remote
        self.state = state
        self.vni = vni

    def __repr__(self):
        return '%s(%s)' % (
            self.__class__.__name__,
            ', '.join('%s=%s' % item for item in vars(self).iteritems())
        )


class Netlink(object):
    """ Provides methods to parse RTNL netlink messages and invoke callbacks
    based on message type.
    """
    # pylint: disable=too-many-instance-attributes
    NETLINK_ROUTE = 0            # Routing/device hook
    NLSOCK_BYTES = 8 * 1024
    __SO_RCVBUFFORCE = 33
    __SOL_NETLINK = 270
    __NETLINK_NO_ENOBUFS = 5
    __BUF_SIZE = 30 * 1024 * 1024

    GROUPS = RtnlGroupType.RTMGRP_LINK
    NEWLINK = RtnlMsgType.RTM_NEWLINK
    DELLINK = RtnlMsgType.RTM_DELLINK

    def __init__(self, process_cb, logger, pool=None):
        self.__process_cbs = process_cb
        self.__logger = logger
        self.__pool = pool or eventlet.GreenPool()
        self.__intfevent = None
        self.__intfqueue = None
        self.__running = set()
        self.dispatcher_gt = None
        self.socket = None

    def __dispatcher(self):
        """ Main thread that drains interface queues by invoking handler
        methods based on message type.

        Netlink messages for different interfaces can be served concurrently,
        however, strict ordering must be maintained between messages
        for the same interface. In order to facilitate this, a queue is
        allocated on a per interface basis, and the dispatcher uses a
        modified FCFS algorithm to schedule threads for messages in interface
        queues.

        Dispatch algorithm:
        The dispatcher monitors the intfevent queue for interface events. On
        receiving a new notification, it checks to see if the there are
        pending netlink messages for the interface. If no other thread is
        serving the same interface, it spawns one to handle the first message
        in the queue. When the new thread is done, it notifies the dispatcher
        by placing the ifindex of the interface in the intfevent queue.
        """
        while True:
            ifindex = self.__intfevent.get()
            if ifindex in self.__intfqueue and ifindex not in self.__running:
                try:
                    msg_type, info = self.__intfqueue[ifindex].get_nowait()
                except eventlet.queue.Empty:
                    self.__intfqueue.pop(ifindex)
                else:
                    self.__running.add(ifindex)
                    green_thread = self.__pool.spawn(
                        self.__process_cbs[msg_type],
                        info
                    )
                    green_thread.link(self.__stop_checker)

    @staticmethod
    def __get_value(attrs, key):
        """ Returns the value associated with a key in attrs.
        """
        return next((val for attr, val in attrs or [] if attr == key), None)

    def __stop_checker(self, green_thread):
        """ Propagates exceptions raised by a green thread to the dispatcher
        green thread.
        """
        ifindex = None
        try:
            ifindex = green_thread.wait()
        except greenlet.GreenletExit:  # pylint: disable=no-member
            pass
        except Exception:  # pylint: disable=broad-except
            eventlet.kill(self.dispatcher_gt, *sys.exc_info())
        self.__running.remove(ifindex)
        self.__intfevent.put(ifindex)

    def bind(self):
        """ Binds the netlink socket and initializes datastructures used for
        communication between dispatcher and server.
        """
        if self.socket is not None:
            try:
                self.socket.close()
            except socket.error:
                # Ignore the error as we will try to rebind
                pass
        self.__intfqueue = collections.defaultdict(eventlet.Queue)
        while self.__running:
            eventlet.sleep(1)
        self.__intfevent = eventlet.Queue()
        try:
            # pylint: disable=no-member
            self.socket = socket.socket(socket.AF_NETLINK,
                                        socket.SOCK_RAW,
                                        self.NETLINK_ROUTE)
            # Set rcv buffer size to 30M (higher than the rmem_max of 8M)
            self.socket.setsockopt(socket.SOL_SOCKET,
                                   self.__SO_RCVBUFFORCE,
                                   self.__BUF_SIZE)
        except socket.error as ex:
            raise RuntimeError('open: socket err: %s' % ex)
        # Open a socket for receiving netlink msgs
        try:
            # PID_MAX_LIMIT is 2^22 allowing 1024 sockets per-pid. We
            # start with 1 in the upper space (top 10 bits) instead of
            # 0 to avoid conflicts with netlink_autobind which always
            # attempts to bind with the pid (and on failure with
            # negative values -4097, -4098, -4099 etc.)
            self.socket.bind((os.getpid() | (1 << 22), Netlink.GROUPS))
        except socket.error as ex:
            raise RuntimeError('bind: socket err: %s' % ex)

    def handle_netlink_msg(self, buf, _):
        """ Parses incoming RTNL netlink messages and places the result
        on the interface queue identified by the ifindex.
        The dispatcher is notified by placing the ifindex on the intfevent
        queue.
        """
        offset = 0
        decoder = Decoder(buf)
        while offset < len(buf):
            msg_len, msg_type = decoder.decode_nlhdr(offset)
            if msg_type in self.__process_cbs:
                try:
                    result = decoder.decode(offset)
                except DecodeError as ex:
                    if ex.code in [DecodeError.RTA_PARSE_ERROR,
                                   DecodeError.UNSUPPORTED_ATTR]:
                        self.__logger.error('Failed to decode netlink msg. %s',
                                            ex.message)
                except Exception:  # pylint: disable=broad-except
                    self.__logger.exception('Error decoding netlink msg.')
                else:
                    linkinfo = result.get(Ifla.IFLA_LINKINFO, None)
                    linkinfo_data = None
                    if linkinfo is not None:
                        linkinfo_data = linkinfo.get(
                            IflaLinkInfo.IFLA_INFO_DATA, None
                        )
                    if linkinfo_data is not None:
                        dev_config = VxlanDevice(
                            result[Decoder.IFINDEX],
                            result[Ifla.IFLA_IFNAME],
                            result[Ifla.IFLA_OPERSTATE],
                            linkinfo_data[IflaVxlan.IFLA_VXLAN_ID],
                            linkinfo_data[IflaVxlan.IFLA_VXLAN_LOCAL],
                            linkinfo_data.get(IflaVxlan.IFLA_VXLAN_PORT, None),
                            linkinfo_data.get(IflaVxlan.IFLA_VXLAN_GROUP, None)
                        )
                        self.__intfqueue[dev_config.ifindex].put((msg_type,
                                                                  dev_config))
                        self.__intfevent.put(dev_config.ifindex)
            offset += Decoder.padded(msg_len)

    def run(self):
        """ Spawns and returns the dispatcher thread.
        """
        self.dispatcher_gt = self.__pool.spawn(self.__dispatcher)
        return self.dispatcher_gt
