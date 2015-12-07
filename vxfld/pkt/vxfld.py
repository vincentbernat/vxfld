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
from abc import ABCMeta
import socket
import struct

from dpkt import dpkt, ethernet, ip, udp

from . import vxfld_pb2

# Protocol version
VERSION = 3

# UDP header byte length
BASE_PKT_SIZE = len(ethernet.Ethernet()) + len(ip.IP()) + len(udp.UDP())


class MsgType(object):
    """ VXFLD message type.
    """
    # pylint: disable=too-few-public-methods
    UNKNOWN = 0     # Never used
    REFRESH = 1     # vxrd <-> vxsnd packet
    PROXY = 2       # vxsnd <-> vxsnd packet for flooding and proxing
    SYNC = 3        # vxsnd <-> vxsnd packet for database syncing

    def __init__(self):
        raise NotImplementedError


class PktError(Exception):
    """ Indicates a malformed packet.
    """
    def __init__(self, msg):
        self.message = msg
        super(PktError, self).__init__()


class ResponseType(object):
    """ Packet response type.
    """
    # pylint: disable=too-few-public-methods
    NONE = 0
    REQUESTED = 1
    ALL = 2

    def __init__(self):
        raise NotImplementedError

class _Refresh(dpkt.Packet):
    """ Common code for Refresh Packets.
    NOTE: provides backward compatibility for protocol versions <= 2.
    Protocol versions >= 3 should use protobuf for
    serialization/deserialization.
    """
    # pylint: disable=missing-docstring
    class VtepsStruct(object):
        """ Provides methods to pack/unpack Vni/IpStruct information to and
        from the packet.
        """
        # pylint: disable=missing-docstring
        __IP_FMT = '4s'
        __IP_LEN = struct.calcsize(__IP_FMT)
        __VTEP_FMT = '>IH'
        __VTEP_LEN = struct.calcsize(__VTEP_FMT)

        def len(self, iplist):
            # pylint: disable=no-member
            return self.__VTEP_LEN + len(iplist) * self.__IP_LEN

        def pack(self, vni, iplist):
            return (
                struct.pack(self.__VTEP_FMT, vni, len(iplist)) +
                ''.join(struct.pack(self.__IP_FMT, socket.inet_aton(ele))
                        for ele in iplist)
            )

        def unpack_from(self, data, offset=0):
            vni, cnt = struct.unpack_from(self.__VTEP_FMT, data, offset)
            offset += self.__VTEP_LEN
            if offset + cnt * self.__IP_LEN > len(data):
                raise PktError('Short packet')
            iplist = []
            for _ in range(cnt):
                iplist.append(
                    socket.inet_ntoa(
                        struct.unpack_from(self.__IP_FMT, data, offset)[0]
                    )
                )
                offset += self.__IP_LEN
            return vni, iplist

    def __init__(self, data=None, **kwargs):
        # Don't call super due to how dpkt works.
        dpkt.Packet.__init__(self, **kwargs)
        self.__vni_vteps = {}
        self.__vtep_struct = self.VtepsStruct()
        # V1 didn't use response_type field.
        if not hasattr(self, 'response_type'):
            setattr(self, 'response_type', ResponseType.ALL)
        if data is not None:
            self.unpack(data)

    def __len__(self):
        # pylint: disable=no-member
        return (
            self.__hdr_len__ + sum(self.ipstr_len(vni, iplist)
                                   for vni, iplist in
                                   self.__vni_vteps.iteritems())
        )

    def __str__(self):
        return (
            self.pack_hdr() +
            ''.join(self.__vtep_struct.pack(vni, iplist)
                    for vni, iplist in self.__vni_vteps.iteritems())
        )

    def ipstr_len(self, _, iplist):
        """ Returns the serialized byte count for iplist.
        :param iplist: list of IP addresses
        :type iplist: list[str]
        :return: serialized byte count for iplist
        """
        return self.__vtep_struct.len(iplist)

    def unpack(self, buf):
        """ Unpacks VNI/VTEP information from the packet.
        :param buf: packet buffer
        """
        dpkt.Packet.unpack(self, buf)
        offset = 0
        while offset < len(self.data):
            vni, iplist = self.__vtep_struct.unpack_from(self.data, offset)
            offset += self.ipstr_len(vni, iplist)
            self.__vni_vteps[vni] = iplist

    @property
    def vni_vteps(self):
        """ Returns the _vni_vteps instance variable.
        :returns: dictionary mapping a VNI to a list of IP addresses
        :rtype: dict[int, list(str)]
        """
        return self.__vni_vteps

    @vni_vteps.setter
    def vni_vteps(self, vteps):
        """ Sets the _vni_vteps instance variable.
        :param vteps: maps a VNI to a list of IP addresses
        :type vteps: dict[int, list[str]]
        """
        for vni, ip_addr_list in vteps.iteritems():
            self.__vni_vteps.setdefault(vni, [])
            self.__vni_vteps[vni].extend(ip_addr_list)


class _RefreshV1(_Refresh):
    """ Older V1 Refresh Packet.
    """
    __hdr__ = (
        ('originator', 'H', 0),  # should be all flags
        ('holdtime', 'H', 0)
    )


class _RefreshV2(_Refresh):
    """ Older V2 Refresh Packet.
    """
    __hdr__ = (
        ('originator', 'H', 0),  # should be all flags
        ('holdtime', 'H', 0),
        ('response_type', 'H', 0)
    )


class Packet(dpkt.Packet):
    """ VXFLD packet header common to all types of messages.
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
        data = self.data or None
        inner = kwargs.get('inner', {})
        if self.type == MsgType.REFRESH:
            if self.version == 1:
                self.data = _RefreshV1(data=data, **inner)
            elif self.version == 2:
                self.data = _RefreshV2(data=data, **inner)
            else:
                self.data = Refresh(data=data, **inner)
        elif self.type == MsgType.PROXY:
            self.data = Proxy(data=data, **inner)
        elif self.type == MsgType.SYNC:
            self.data = Sync(data=data, **inner)


class Pb2Base(object):
    """ Base class for all protobuf messages.
    """
    # pylint: disable=no-member,missing-docstring,too-few-public-methods
    __metaclass__ = ABCMeta

    def __init__(self, cls, data=None, **kwargs):
        object.__setattr__(self, '_msg', cls(**kwargs))
        if data is not None:
            self._msg.ParseFromString(data)

    def __len__(self):
        return self._msg.ByteSize()

    def __getattr__(self, item):
        return getattr(self._msg, item)

    def __setattr__(self, key, value):
        try:
            object.__getattribute__(self, key)
        except AttributeError:
            setattr(self._msg, key, value)
        else:
            object.__setattr__(self, key, value)

    def __str__(self):
        return self._msg.SerializeToString()

    @staticmethod
    def _ipv4_pack(field, value):
        """ Packs an IPv4 address into a protobuf message
        :param field: protobuf field
        :type field: vxfld_pb2.IPv4Address
        :param value: IPv4 address string
        """
        field.address.extend(int(ele) for ele in value.split('.'))

    @staticmethod
    def _ipv4_unpack(field):
        """ Unpacks an IPv4 address from a protobuf message.
        :param field: protobuf field
        :type field: vxfld_pb2.IPv4Address
        :returns: IPv4 address string
        """
        return '.'.join(str(ele) for ele in field.address)


class Proxy(Pb2Base):
    """ Proxy message from vxsnd to vxsnd.
    """
    # pylint: disable=attribute-defined-outside-init
    def __init__(self, data=None, **kwargs):
        object.__setattr__(self, 'srcip_a', None)
        super(Proxy, self).__init__(vxfld_pb2.Proxy, data=data, **kwargs)

    def add_proxy_ip(self, ip_addr):
        """ Adds an address to the list of proxy IP addresses.
        :param ip_addr: proxy IP address
        """
        if self._msg.proxy_ips and ip_addr not in self._msg.proxy_ips:
            ele = self._msg.proxy_ips.add()
            self._ipv4_pack(ele, ip_addr)
            self._msg.proxy_hops += 1

    @property
    def srcip(self):
        """ Returns the sending VTEP's source IP address.
        :returns: sending VTEP's source IP address
        """
        if self.srcip_a is None:
            self.srcip_a = self._ipv4_unpack(self._msg.srcip_n)
        return self.srcip_a

    @srcip.setter
    def srcip(self, value):
        """ Sets the sending VTEP's source IP address.
        :param value: sending VTEP's source IP address
        """
        self.srcip_a = value
        self._ipv4_pack(self._msg.srcip_n, value)


class Refresh(Pb2Base):
    """ Refresh message from vxrd to vxsnd.
    """
    # pylint: disable=no-member,missing-docstring
    def __init__(self, data=None, **kwargs):
        super(Refresh, self).__init__(vxfld_pb2.Refresh, data=data, **kwargs)

    @classmethod
    def __serialize(cls, vtep):
        vni_dict = vxfld_pb2.Refresh.VniDict()
        for vni, elements in vtep.items():
            vni_dict.vni = vni
            for ele in elements:
                entry = vni_dict.data.add()
                cls._ipv4_pack(entry.ip_addr, ele)
        return vni_dict

    @classmethod
    def ipstr_len(cls, vni, data):
        """ Returns the serialized byte count for {vni: data}.
        :param vni: VXLAN network identifier
        :param data: list of IP addresses
        :type data: list[str]
        :return: serialized byte count for {vni: data}
        """
        return cls.__serialize({vni: data}).ByteSize()

    @property
    def vni_vteps(self):
        """ Returns the _vni_vteps instance variable.
        :returns: dictionary mapping a VNI to a list of IP addresses
        :rtype: dict[int, list[str]]
        """
        output = {}
        for vtep in self._msg.vteps:
            output.setdefault(vtep.vni, [])
            output[vtep.vni].extend(self._ipv4_unpack(entry.ip_addr)
                                    for entry in vtep.data)
        return output

    @vni_vteps.setter
    def vni_vteps(self, vteps):
        """ Sets the _vni_vteps instance variable.
        :param vteps: maps a VNI to a list of IP addresses
        :type vteps: dict[int, list[str]]
        """
        for vni, entries in vteps.iteritems():
            vtep = self._msg.vteps.add()
            vtep.CopyFrom(self.__serialize({vni: entries}))


class Sync(Pb2Base):
    """ Sync message from vxsnd to vxsnd.
    """
    # pylint: disable=no-member,missing-docstring
    def __init__(self, data=None, **kwargs):
        super(Sync, self).__init__(vxfld_pb2.Sync, data=data, **kwargs)

    @classmethod
    def __serialize(cls, vtep):
        vni_dict = vxfld_pb2.Sync.VniDict()
        for vni, elements in vtep.items():
            vni_dict.vni = vni
            for ele in elements:
                entry = vni_dict.data.add()
                ip_addr, entry.holdtime, entry.identifier = ele
                cls._ipv4_pack(entry.ip_addr, ip_addr)
        return vni_dict

    @classmethod
    def ipstr_len(cls, vni, data):
        """ Returns the serialized byte count for {vni: data}.
        :param vni: VXLAN network identifier
        :param data: list of tuples composed of an IP address, holdtime and
                     node identifier
        :type data: list[(str, int, int)]
        :return: serialized byte count for {vni: data}
        """
        return cls.__serialize({vni: data}).ByteSize()

    @property
    def vni_vteps(self):
        """ Returns the _vni_vteps instance variable.
        :returns: dictionary mapping a VNI to a list of tuples composed of an
                  IP address, holdtime and node identifier
        :rtype: dict[int, list[(str, int, int)]]
        """
        output = {}
        for vtep in self._msg.vteps:
            output.setdefault(vtep.vni, [])
            output[vtep.vni].extend((self._ipv4_unpack(entry.ip_addr),
                                     entry.holdtime, entry.identifier)
                                    for entry in vtep.data)
        return output

    @vni_vteps.setter
    def vni_vteps(self, vteps):
        """ Sets the _vni_vteps instance variable.
        :param vteps: maps a VNI to a list of tuples composed of an IP
                      address, holdtime and node identifier
        :type vteps: dict[int, list[(str, int, int)]]
        """
        for vni, entries in vteps.iteritems():
            vtep = self._msg.vteps.add()
            vtep.CopyFrom(self.__serialize({vni: entries}))
