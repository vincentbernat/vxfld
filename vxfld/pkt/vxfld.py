# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2014, 2015 Cumulus Networks, Inc. All rights reserved.
# Copyright (C) 2014 Metacloud Inc.
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
""" This modules provides classes used for packet processing.
"""
import socket
import struct

from dpkt import dpkt, ethernet, ip, udp

# Protocol version
VERSION = 2

# UDP header length
BASE_PKT_SIZE = len(ethernet.Ethernet()) + len(ip.IP()) + len(udp.UDP())


class MsgType(object):
    """ VXFLD message types.
    """
    # pylint: disable=too-few-public-methods
    UNKNOWN = 0     # Never used
    REFRESH = 1     # vxrd <-> vxsnd packet
    PROXY = 2       # vxsnd <-> vxsnd packet for flooding and proxing

    def __init__(self):
        raise NotImplementedError


class ResponseType(object):
    """ Refresh packet response types.
    """
    # pylint: disable=too-few-public-methods
    NONE = 0
    REQUESTED = 1
    ALL = 2

    def __init__(self):
        raise NotImplementedError


class PktError(Exception):
    """ Indicates a malformed packet.
    """
    def __init__(self, msg):
        self.message = msg
        super(PktError, self).__init__()


class _Refresh(dpkt.Packet):
    """ Common Code for Refresh Packets.
    """
    def __init__(self, data=None, version=VERSION, **kwargs):
        # Don't call super due to how dpkt works
        dpkt.Packet.__init__(self, **kwargs)
        self.version = version
        self.type = MsgType.REFRESH
        self.vni_vteps = dict()
        if data is not None:
            self.unpack(data)
        # V1 didn't use response_type field, it just always send it.
        if not hasattr(self, 'response_type'):
            setattr(self, 'response_type', ResponseType.ALL)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        data = self.data
        pos = 0
        data_len = len(data)
        while pos < data_len:
            vni, cnt = struct.unpack('>IH', data[pos:pos + 6])
            pos += 6
            if pos + cnt * 4 > data_len:
                raise PktError('Short packet')
            if not self.vni_vteps.get(vni, None):
                self.vni_vteps[vni] = []
            while cnt:
                ip_addr = data[pos:pos + 4]
                self.vni_vteps[vni].append(socket.inet_ntoa(ip_addr))
                cnt -= 1
                pos += 4

    @staticmethod
    def vtep_to_str(vni, iplist):
        return (
            struct.pack('>IH', vni, len(iplist)) +
            ''.join(socket.inet_aton(ip_addr) for ip_addr in iplist)
        )

    def __str__(self):
        return (
            self.pack_hdr() +
            ''.join(self.vtep_to_str(vni, iplist)
                    for vni, iplist in self.vni_vteps.items())
        )

    def __len__(self):
        cnt = 0
        for _, iplist in self.vni_vteps.items():
            cnt += 4 + 2 + 4 * len(iplist)
        return self.__hdr_len__ + cnt  # pylint: disable=no-member

    def add_vni_vteps(self, vteps):
        """ Add a set of <vni vtep_list>.
        """
        for vni, ip_addr_list in vteps.items():
            iplist = self.vni_vteps.get(vni, None)
            if iplist:
                iplist.extend(ip_addr_list)
            else:
                self.vni_vteps[vni] = ip_addr_list


class _RefreshV1(_Refresh):
    """ Older V1 Refresh Packet.
    """
    __hdr__ = (
        ('originator', 'H', 0),  # should be all flags
        ('holdtime', 'H', 0)
    )


class Refresh(_Refresh):
    """ Refresh Packet.
    """
    __hdr__ = (
        ('originator', 'H', 0),  # should be all flags
        ('holdtime', 'H', 0),
        ('response_type', 'H', 0)
    )


class Proxy(dpkt.Packet):
    """ VXFLD proxy request from vxsnd to vxsnd.
    """
    # pylint: disable=no-member
    __hdr__ = (
        ('ttl', 'H', 4),                # TTL
        ('proxy_hops', 'h', 0),         # How many hops this packet has seen
        ('srcport', 'H', 0x0),          # Sending VTEPs source port
        ('srcip_n', '4s', '\x00' * 4),  # Sending VTEPs source IP
        ('area', 'H', 0)                # VXLAN area ID
    )

    @property
    def srcip(self):
        """ SrcIp
        """
        if self.srcip_a is None:
            self.srcip_a = socket.inet_ntoa(self.srcip_n)
        return self.srcip_a

    @srcip.setter
    def srcip(self, srcip):
        """ Sets the sending VTEP source IP address in the VXFLD proxy packet.
        """
        # pylint: disable=attribute-defined-outside-init
        self.srcip_a = srcip
        self.srcip_n = socket.inet_aton(srcip)

    def __init__(self, data=None, **kwargs):
        # Don't call super due to how dpkt works
        dpkt.Packet.__init__(self, **kwargs)
        self.srcip_a = None
        self.proxy_ips = []
        self.vxlan_pkt = None
        if data is not None:
            self.unpack(data)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        data = self.data
        pos = 0
        data_len = len(data)
        cnt = 0
        while cnt < self.proxy_hops:
            ip_addr = data[pos:pos + 4]
            self.proxy_ips.append(socket.inet_ntoa(ip_addr))
            cnt += 1
            pos += 4
        self.vxlan_pkt = data[pos:data_len]

    def __str__(self):
        return (
            self.pack_hdr() +
            ''.join(socket.inet_aton(ip_addr) for ip_addr in self.proxy_ips) +
            str(self.vxlan_pkt)
        )

    def add_proxy_ip(self, ip_addr):
        """ add_proxy_ip
        """
        if self.proxy_ips is not None and ip_addr not in self.proxy_ips:
            self.proxy_ips.append(ip_addr)
            self.proxy_hops += 1


class Packet(dpkt.Packet):
    """ VXLFD packets are sent between vxsnd and vxrd entities.
    """
    __hdr__ = (
        ('version', 'B', VERSION),  # version of the protocol Packet
        ('type', 'B', 0),
    )

    def __init__(self, *args, **kwargs):
        # Don't call super due to how dpkt works
        # pylint: disable=no-member
        dpkt.Packet.__init__(self, **kwargs)
        if args:
            dpkt.Packet.unpack(self, args[0])
            if self.version > VERSION:
                raise PktError('Unknown Protocol Version')
            if self.type == MsgType.REFRESH:
                if self.version == 1:
                    self.data = _RefreshV1(data=self.data,
                                           version=self.version)
                else:
                    self.data = Refresh(data=self.data, version=self.version)
            elif self.type == MsgType.PROXY:
                self.data = Proxy(data=self.data)
