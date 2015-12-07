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
""" This module provides methods to parse RTNL messages.
"""
import socket
import struct

from vxfld.common.enums import OperState


class DecodeError(Exception):
    """ Indicates an error in decoding a packet.
    """
    # pylint: disable=too-few-public-methods
    RTA_PARSE_ERROR = 0
    UNSUPPORTED_ATTR = 1
    UNSUPPORTED_KIND = 2

    def __init__(self, code, message, *args, **kwargs):
        self.code = code
        self.message = message
        super(DecodeError, self).__init__(*args, **kwargs)


class _DecodeType(object):
    """ Provides methods to extract data from the packet based on the
    type of attribute.
    """
    # pylint: disable=missing-docstring,too-few-public-methods
    UINT8 = 0
    UINT16 = 1
    UINT32 = 2
    IPV4ADDR = 3
    STRING = 4

    @staticmethod
    def __decode_uint8(data, offset):
        return struct.unpack_from('B', data, offset)[0]

    @staticmethod
    def __decode_uint16(data, offset):
        return struct.unpack_from('H', data, offset)[0]

    @staticmethod
    def __decode_uint32(data, offset):
        return struct.unpack_from('I', data, offset)[0]

    @staticmethod
    def __decode_ipv4addr(data, offset):
        address = struct.unpack_from('4s', data, offset)[0]
        return socket.inet_ntop(socket.AF_INET, address)

    @staticmethod
    def __decode_string(data, offset, length):
        # null terminated string
        return struct.unpack_from('%ds' % (length - 1), data, offset)[0]

    @classmethod
    def decode(cls, attr_type, data, offset, length=0):
        """ Returns a value based on the type of attribute.
        :param attr_type: one of the variables of this class
        :param data: packet buffer
        :param offset: offset for decoding
        :param length: rta length; needed for decoding string type attributes
        :returns: decoded value based on the type of attribute
        """
        offset += Decoder.RTATTR_LEN
        if attr_type == cls.UINT8:
            return cls.__decode_uint8(data, offset)
        elif attr_type == cls.UINT16:
            return cls.__decode_uint16(data, offset)
        elif attr_type == cls.UINT32:
            return cls.__decode_uint32(data, offset)
        elif attr_type == cls.IPV4ADDR:
            return cls.__decode_ipv4addr(data, offset)
        elif attr_type == cls.STRING:
            return cls.__decode_string(data, offset,
                                       length - Decoder.RTATTR_LEN)
        else:
            raise DecodeError(DecodeError.UNSUPPORTED_ATTR,
                              '%s is not supported' % attr_type)


class Ifla(object):
    """ Link level constants not dependent on network protocol.
    Defined in /usr/include/linux/if_link.h
    """
    # pylint: disable=too-few-public-methods
    IFLA_UNSPEC = 0
    IFLA_ADDRESS = 1
    IFLA_BROADCAST = 2
    IFLA_IFNAME = 3
    IFLA_MTU = 4
    IFLA_LINK = 5
    IFLA_QDISC = 6
    IFLA_STATS = 7
    IFLA_COST = 8
    IFLA_PRIORITY = 9
    IFLA_MASTER = 10
    IFLA_WIRELESS = 11          # Wireless Extension event - see wireless.h
    IFLA_PROTINFO = 12          # Protocol specific information for a link
    IFLA_TXQLEN = 13
    IFLA_MAP = 14
    IFLA_WEIGHT = 15
    IFLA_OPERSTATE = 16
    IFLA_LINKMODE = 17
    IFLA_LINKINFO = 18
    IFLA_NET_NS_PID = 19
    IFLA_IFALIAS = 20
    IFLA_NUM_VF = 21            # Number of VFs if device is SR-IOV PF
    IFLA_VFINFO_LIST = 22
    IFLA_STATS64 = 23
    IFLA_VF_PORTS = 24
    IFLA_PORT_SELF = 25
    IFLA_AF_SPEC = 26
    IFLA_GROUP = 27             # Group the device belongs to
    IFLA_NET_NS_FD = 28
    IFLA_EXT_MASK = 29          # Extended info mask, VFs, etc
    IFLA_LINKPROTODOWN = 200
    IFLA_MAX = 200

    def __init__(self):
        raise NotImplementedError


class IflaLinkInfo(object):
    """ IFLA_LINKINFO attributes not dependent on network protocol.
    Defined in /usr/include/linux/if_link.h
    """
    # pylint: disable=too-few-public-methods
    IFLA_INFO_UNSPEC = 0
    IFLA_INFO_KIND = 1
    IFLA_INFO_DATA = 2
    IFLA_INFO_XSTATS = 3
    IFLA_INFO_MAX = 4

    def __init__(self):
        raise NotImplementedError


class IflaVxlan(object):
    """ IFLA_LINKINFO_DATA attributes for VXLAN.
    """
    # pylint: disable=too-few-public-methods
    IFLA_VXLAN_UNSPEC = 0
    IFLA_VXLAN_ID = 1
    IFLA_VXLAN_GROUP = 2
    IFLA_VXLAN_LINK = 3
    IFLA_VXLAN_LOCAL = 4
    IFLA_VXLAN_TTL = 5
    IFLA_VXLAN_TOS = 6
    IFLA_VXLAN_LEARNING = 7
    IFLA_VXLAN_AGEING = 8
    IFLA_VXLAN_LIMIT = 9
    IFLA_VXLAN_PORT_RANGE = 10
    IFLA_VXLAN_PROXY = 11
    IFLA_VXLAN_RSC = 12
    IFLA_VXLAN_L2MISS = 13
    IFLA_VXLAN_L3MISS = 14
    IFLA_VXLAN_PORT = 15
    IFLA_VXLAN_GROUP6 = 16
    IFLA_VXLAN_LOCAL6 = 17
    IFLA_VXLAN_UDP_CSUM = 18
    IFLA_VXLAN_UDP_ZERO_CSUM6_TX = 19
    IFLA_VXLAN_UDP_ZERO_CSUM6_RX = 20
    IFLA_VXLAN_REMCSUM_TX = 21
    IFLA_VXLAN_REMCSUM_RX = 22
    IFLA_VXLAN_GBP = 23
    IFLA_VXLAN_REMCSUM_NOPARTIAL = 24
    IFLA_VXLAN_COLLECT_METADATA = 25

    # Attributes of interest to us.
    DECODE_MAP = {
        IFLA_VXLAN_ID: _DecodeType.UINT32,
        IFLA_VXLAN_GROUP: _DecodeType.IPV4ADDR,
        IFLA_VXLAN_LINK: _DecodeType.UINT32,
        IFLA_VXLAN_LOCAL: _DecodeType.IPV4ADDR,
        IFLA_VXLAN_PORT: _DecodeType.UINT16,
    }

    def __init__(self):
        raise NotImplementedError

    @classmethod
    def decode(cls, rta_type, data, offset):
        """ Returns a value based on the type of attribute.
        :param rta_type: type of attribute
        :param data: packet buffer
        :param offset: starting offset
        :returns: decoded value based on rta type
        """
        return _DecodeType.decode(cls.DECODE_MAP[rta_type], data, offset)


class RtnlGroupType(object):
    """ RTNL group type.
    Defined in /usr/include/linux/rtnetlink.h
    """
    # pylint: disable=too-few-public-methods
    RTMGRP_LINK = 0x1
    RTMGRP_IPV4_IFADDR = 0x10
    RTMGRP_IPV4_ROUTE = 0x40
    RTMGRP_IPV6_IFADDR = 0x100
    RTMGRP_IPV6_ROUTE = 0x400

    def __init__(self):
        raise NotImplementedError


class RtnlMsgType(object):
    """ RTNL message type.
    Defined in /usr/include/linux/rtnetlink.h
    """
    # pylint: disable=too-few-public-methods
    RTM_NEWLINK = 16
    RTM_DELLINK = 17
    RTM_GETLINK = 18
    RTM_SETLINK = 19
    RTM_NEWADDR = 20
    RTM_DELADDR = 21
    RTM_GETADDR = 22
    RTM_NEWROUTE = 24
    RTM_DELROUTE = 25
    RTM_GETROUTE = 26

    def __init__(self):
        raise NotImplementedError


class Decoder(object):
    """ Provides methods to extract attributes from a netlink message.
    """
    __ALIGN_TO = 4

    __IFINFOMSG_FMT = 'BBHiII'
    __IFINFOMSG_LEN = struct.calcsize(__IFINFOMSG_FMT)

    __NLMSG_FMT = 'IHHII'
    __NLMSG_LEN = struct.calcsize(__NLMSG_FMT)

    __RTATTR_FMT = '=HH'

    IFINDEX = 'ifindex'
    RTATTR_LEN = struct.calcsize(__RTATTR_FMT)

    SUPPORTED_KINDS = ['vxlan']

    def __init__(self, data):
        self.__data = data

    @staticmethod
    def padded(length):
        """ Returns length aligned to the ALIGN_TO byte boundary
        """
        return (length + Decoder.__ALIGN_TO - 1) & ~(Decoder.__ALIGN_TO - 1)

    def decode_ifinfomsg(self, offset=0):
        """ Decodes an IFINFO message.
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Family    |   Reserved  |          Device Type              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                     Interface Index                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                      Device Flags                             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                      Change Mask                              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        :param offset: offset for decoding
        :returns: ifi_index in the message
        """
        _, _, _, ifi_index, _, _ = (
            struct.unpack_from(self.__IFINFOMSG_FMT,
                               self.__data,
                               offset + self.__NLMSG_LEN)
        )
        return ifi_index

    def decode_nlhdr(self, offset=0):
        """ Decodes the netlink header.
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                          Length                             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |            Type              |           Flags              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                      Sequence Number                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                      Process ID (PID)                       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        :param offset: offset for decoding
        :returns: tuple composed of the netlink message length and netlink
                  message type.
        """
        nlmsg_len, nlmsg_type, _, _, _ = (
            struct.unpack_from(self.__NLMSG_FMT, self.__data, offset)
        )
        return nlmsg_len, nlmsg_type

    def decode_rtas(self, msg_len, offset=0, linkinfo=False,
                    linkinfo_data=False):
        """ Extracts IFLA attributes from a netlink message.
        :param msg_len: message length
        :param offset: offset for decoding
        :param linkinfo: set to True for IflaLinkInfo attributes
        :param linkinfo_data: set to True for IflaVxlan attributes
        :return: dictionary mapping link attributes to their values extracted
                 from the message.
        """
        result = {}
        while msg_len - offset >= self.RTATTR_LEN:
            rta_len, rta_type = struct.unpack_from(self.__RTATTR_FMT,
                                                   self.__data,
                                                   offset)
            if not self.RTATTR_LEN <= rta_len <= msg_len - offset:
                raise DecodeError(DecodeError.RTA_PARSE_ERROR,
                                  'Error parsing message')
            if linkinfo:
                if rta_type == IflaLinkInfo.IFLA_INFO_KIND:
                    kind = _DecodeType.decode(_DecodeType.STRING,
                                              self.__data, offset, rta_len)
                    if kind not in self.SUPPORTED_KINDS:
                        raise DecodeError(DecodeError.UNSUPPORTED_KIND,
                                          'Unsupported IFLA_INFO_KIND %s' %
                                          kind)
                    result[IflaLinkInfo.IFLA_INFO_KIND] = kind
                elif rta_type == IflaLinkInfo.IFLA_INFO_DATA:
                    result[IflaLinkInfo.IFLA_INFO_DATA] = (
                        self.decode_rtas(offset + rta_len,
                                         offset + self.RTATTR_LEN,
                                         linkinfo_data=True)
                    )
            elif linkinfo_data:
                if rta_type in IflaVxlan.DECODE_MAP:
                    result[rta_type] = IflaVxlan.decode(rta_type,
                                                        self.__data,
                                                        offset)
            else:
                if rta_type == Ifla.IFLA_IFNAME:
                    result[rta_type] = _DecodeType.decode(_DecodeType.STRING,
                                                          self.__data,
                                                          offset,
                                                          rta_len)
                elif rta_type == Ifla.IFLA_OPERSTATE:
                    operstate = _DecodeType.decode(_DecodeType.UINT8,
                                                   self.__data,
                                                   offset)
                    result[rta_type] = OperState.OPERSTATE_STR[operstate]
                elif rta_type == Ifla.IFLA_LINKINFO:
                    result[Ifla.IFLA_LINKINFO] = (
                        self.decode_rtas(offset + rta_len,
                                         offset + self.RTATTR_LEN,
                                         linkinfo=True)
                    )
            offset += self.padded(rta_len)
        return result

    def decode(self, offset=0):
        """ Decodes a RTNL message.
        :param offset: offset for decoding
        :returns: dictionary mapping link attributes to their values extracted
                  from the message
        """
        result = {}
        nlmsg_len, _ = self.decode_nlhdr(offset)
        ifi_index = self.decode_ifinfomsg(offset)
        result[self.IFINDEX] = ifi_index
        result.update(self.decode_rtas(offset + nlmsg_len,
                                       offset + self.__NLMSG_LEN +
                                       self.__IFINFOMSG_LEN))
        return result
