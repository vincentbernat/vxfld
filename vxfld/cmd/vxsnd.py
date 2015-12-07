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
""" This module provides classes used by the VXLAN service node Daemon (vxsnd).
"""
import atexit
import collections
import logging
from random import sample
import socket
import subprocess
import time

import dpkt
import eventlet
import eventlet.pools

from vxfld.common import config, service, utils
from vxfld.common.enums import NodeType
from vxfld.pkt import vxfld as VXFLD
from vxfld.pkt.vxlan import VXLAN

NODE_TYPE = NodeType.VXSND


class _Fdb(object):
    """ This class provides CRUD methods for the service node daemon's
    forwarding database.
    """
    # The default identifier is used for addresses that are dynamically
    # learned (software replication) or statically configured.
    DEFAULT_ID = 0

    # Holdtimer is an 8 bit field.
    NO_AGE = 65535

    class NodeConfig(object):
        """ VTEP information stored on a per VNI basis.
        """
        # pylint: disable=too-few-public-methods
        def __init__(self, addr, ageout=None, identifier=None):
            self.addr = addr
            self.ageout = ageout
            self.identifier = identifier or _Fdb.DEFAULT_ID

        def __eq__(self, other):
            return (isinstance(other, _Fdb.NodeConfig) and
                    self.key() == other.key())

        def __hash__(self):
            return hash(self.key())

        def __ne__(self, other):
            return not self == other

        def __repr__(self):
            return '%s(addr=%s, ageout=%s, identifier=%s)' % (
                self.__class__.__name__, self.addr, self.ageout,
                self.identifier
            )

        def key(self):
            """ Guarantees the uniqueness of an <addr, id> in a set
            """
            return '%s%s' % (self.addr, self.identifier)

    def __init__(self, logger):
        """:type : set[NodeConfig]"""
        self.__data = {}
        self.__logger = logger

    def __iter__(self):
        return iter(self.__data)

    def __str__(self):
        return ', '.join('%d: %s' % (vni, vni_set)
                         for vni, vni_set in self.__data.iteritems())

    @staticmethod
    def __find(vni_set, entry):
        """ Locates an entry in the vni_set passed to this method.
        :returns: NodeConfig object if successful, otherwise None
        """
        return next((ele for ele in vni_set if entry == ele), None)

    def ageout(self):
        """ Ages out an IP address for an VNI. Removes the VNI from the
        FDB when all addresses have been aged out.
        """
        now = int(time.time())
        new_fdb = {}
        for vni, vni_set in self.__data.iteritems():
            new_vni_set = {ele for ele in vni_set
                           if now <= ele.ageout or ele.ageout == self.NO_AGE}
            difference = vni_set - new_vni_set
            if difference:
                self.__logger.debug('Aged out addresses for VNI: %s are '
                                    '%s', vni, ', '.join(ele.addr for ele in
                                                         difference))
            if new_vni_set:
                new_fdb[vni] = new_vni_set
        self.__data = new_fdb

    def get(self, vni, now=None):
        """ Returns information for all VTEPs in a VNI.
        :param vni: VXLAN network identifier
        :param now: current timestamp
        :returns: list of tuples composed of the ip address, adjusted
                  holdtime and node identifier
        """
        now = now or int(time.time())
        ret = []
        for entry in self.__data.get(vni, []):
            holdtime = entry.ageout
            if holdtime != self.NO_AGE:
                holdtime = entry.ageout - now
            ret.append((entry.addr, holdtime, entry.identifier))
        return ret

    def get_addrs(self, vni):
        """ Returns all IP addresses in a VNI.
        """
        return {ele.addr for ele in self.__data.get(vni, set())}

    def get_static_addrs(self):
        """ Returns all static IP addresses in the FDB.
        :returns: dictionary mapping VNIs to IP addresses
        :rtype: dict[int, set[str]]
        """
        ret = {}
        for vni, ele_set in self.__data.iteritems():
            addr_set = {ele.addr for ele in ele_set
                        if ele.ageout == _Fdb.NO_AGE}
            if addr_set:
                ret[vni] = addr_set
        return ret

    def refresh(self, vni, addr, holdtime, identifier=None):
        """ Refreshes a <vni, addr, id> in the FDB.
        :param vni: VXLAN network identifier
        :param addr: VTEP ip address
        :param holdtime: packet holdtime
        :param identifier: identifies the source of an address
        """
        if holdtime == self.NO_AGE:
            return
        vni_set = self.__data.get(vni, set())
        entry = self.NodeConfig(addr,
                                identifier=int(identifier or self.DEFAULT_ID))
        ele = self.__find(vni_set, entry)
        if ele is not None:
            ele.ageout = int(time.time()) + holdtime

    def rel_holdtime(self, vni=None):
        """ Returns a copy of the fdb with the hold times adjusted to
        be relative rather than absolute. Used for display purposes.
        :param vni: VXLAN network identifier
        :returns: dictionary mapping VNIs to tuples composed of the IP address,
                  adjusted holdtime and node identifier
        :rtype: dict[int, (str, int | str, int | str)]
        """
        now = int(time.time())
        if vni is None:
            vni_dict = {v: self.get(v, now=now) for v in self.__data}
        else:
            vni_dict = {vni: self.get(vni)}
        output_dict = collections.defaultdict(list)
        for vni, vni_data in vni_dict.iteritems():
            for addr, holdtime, identifier in vni_data:
                holdtime_str = str(holdtime)
                if holdtime == self.NO_AGE:
                    holdtime_str = 'STATIC'
                identifier_str = str(identifier)
                if identifier == self.DEFAULT_ID:
                    identifier_str = ''
                output_dict[vni].append((addr, holdtime_str, identifier_str))
        return output_dict

    def remove(self, vni, addr, identifier):
        """ Deletes the <vni, addr, id> from the fdb.
        :param vni: VXLAN network identifier
        :param addr: VTEP IP address
        :param identifier: identifies the source of an address
        """
        if vni not in self.__data:
            return
        vni_set = self.__data[vni]
        entry = self.NodeConfig(addr, identifier=identifier)
        ele = self.__find(vni_set, entry)
        if ele is not None:
            vni_set.remove(ele)
            if not vni_set:
                del self.__data[vni]

    def update(self, vni, addr, holdtime, identifier=None):
        """ Updates this <vni, addr, id> in the fdb. Just update the ageout if
        the <vni, addr, id> is already in the FDB.
        :param vni: VXLAN network identifier
        :param addr: VTEP ip address
        :param holdtime: packet holdtime
        :param identifier: identifies the source of an address
        """
        ageout = holdtime
        if ageout != self.NO_AGE:
            ageout = int(time.time()) + holdtime
        identifier = int(identifier or self.DEFAULT_ID)
        self.__data.setdefault(vni, set())
        vni_set = self.__data[vni]
        entry = self.NodeConfig(addr, ageout=ageout, identifier=identifier)
        # the default identifier does not need to be unique in the vni_set
        if identifier != self.DEFAULT_ID:
            ele = next((ele for ele in vni_set
                        if ele.identifier == entry.identifier), None)
            if ele is not None:
                vni_set.remove(ele)
        if entry not in vni_set:
            vni_set.add(entry)
        else:
            self.refresh(vni, addr, holdtime, identifier=identifier)


class _Vxsnd(service.Vxfld):
    """ Main Class that provides methods used by VXLAN Service Node Daemon.
    """
    __VXFLD_PKT_BURST_SIZE = 32

    def __init__(self, conf):
        super(_Vxsnd, self).__init__(conf)
        # Addresses for receiving control traffic
        self.__vxfld_refresh_servers = {
            (ip_addr, self._conf.vxfld_port)
            for ip_addr, _ in self._conf.svcnode_peers
        }
        # Addresses for sending refresh messages
        if '0.0.0.0' in {self._conf.src_ip, self._conf.svcnode_ip}:
            self.__vxfld_addresses = {
                ('0.0.0.0', self._conf.vxfld_port)
            }
        else:
            self.__vxfld_addresses = {
                (self._conf.src_ip, self._conf.vxfld_port),
                (self._conf.svcnode_ip, self._conf.vxfld_port)
            }
        # Socket for inter-snd communication
        self.__isocketpool = eventlet.pools.Pool(max_size=1)
        # Socket for flooding
        if not self._conf.no_flood:
            self.__aton_cache = {}
            self.__fsocketpool = eventlet.pools.Pool(max_size=1)
        self.__fdb = _Fdb(self._logger)
        self.__sync_response = False

    def _process(self, msg):
        """ Process requests from a mgmt. client.
        :returns: tuple composed of a result object and Exception.
                  Latter would be None if everything is good.
        """
        # pylint: disable=too-many-branches
        ret = (None, RuntimeError('Unknown error'))
        try:
            if msg['fdb']:
                if any(msg.get(key, None) for key in ['add', 'del', 'file']):
                    if msg['file']:
                        self._logger.info('MgmtServer: fdb file %s',
                                          msg['<filename>'])
                        # delete existing static addresses from the FDB
                        vni_dict = self.__fdb.get_static_addrs()
                        self.__update_fdb(vni_dict, 0)
                        # add static addresses from the file to the FDB
                        vni_dict = collections.defaultdict(set)
                        try:
                            with open(msg['<filename>']) as fdesc:
                                for line in fdesc:
                                    vni, ip_addr = line.split()
                                    socket.inet_aton(ip_addr)
                                    vni_dict[int(vni)].add(ip_addr)
                        except Exception:  # pylint: disable=broad-except
                            ret = (None, 'Failed to parse file %s' %
                                   msg['<filename>'])
                        else:
                            self.__update_fdb(vni_dict, _Fdb.NO_AGE)
                            ret = (None, None)
                    else:
                        vni = int(msg['<vni>'])
                        ip_addr = msg['<ip>']
                        socket.inet_aton(ip_addr)
                        holdtime = _Fdb.NO_AGE if msg['add'] else 0
                        self._logger.info('MgmtServer: fdb %s %s %s',
                                          'add' if msg['add'] else 'del',
                                          vni, ip_addr)
                        self.__update_fdb({vni: {ip_addr}}, holdtime)
                        ret = (None, None)
                else:
                    self._logger.info('MgmtServer: get fdb')
                    vni = None
                    if msg['<vni>']:
                        vni = int(msg['<vni>'])
                    ret = (self.__fdb.rel_holdtime(vni), None)
            elif msg['get'] and msg['config']:
                if msg['<parameter>'] is not None:
                    parameter = msg['<parameter>']
                    self._logger.info('MgmtServer: get config %s', parameter)
                    parameters = self._conf.get_params()
                    if parameter in parameters:
                        value = parameters.get(parameter, None)
                        ret = ({parameter: value}, None)
                    else:
                        self._logger.error('MgmtServer: unknown parameter %s',
                                           parameter)
                        ret = (None, RuntimeError('Unknown parameter'))
                else:
                    self._logger.info('MgmtServer: get config')
                    ret = (self._conf.get_params(), None)
            elif msg['set'] and msg['config']:
                parameter = msg['<parameter>']
                if parameter in self._conf.get_params():
                    if self._conf.is_reloadable(parameter):
                        value = msg['<value>']
                        if (value is None and
                                not self._conf.is_nullable(parameter)):
                            self._logger.error('MgmtServer: %s cannot be None',
                                               parameter)
                            ret = (None, RuntimeError('Value cannot be None'))
                        else:
                            try:
                                # pylint: disable=broad-except
                                self._logger.info('MgmtServer: set config %s '
                                                  '= %s', parameter, value)
                                self._conf.set_param(parameter, value)
                                parameters = self._conf.get_params()
                                value = parameters.get(parameter, None)
                                ret = ({parameter: value}, None)
                            except Exception as ex:
                                self._logger.error('MgmtServer: unknown error '
                                                   '%s', ex.message)
                                ret = (None, RuntimeError(ex.message))
                    else:
                        self._logger.error('MgmtServer: %s is read-only',
                                           parameter)
                        ret = (None, RuntimeError('Read-Only Parameter'))
                else:
                    self._logger.error('MgmtServer: Unknown parameter %s',
                                       parameter)
                    ret = (None, RuntimeError('Unknown parameter'))
            elif msg['set'] and msg['debug']:
                if msg['on']:
                    try:
                        self._conf.set_param('debug', True)
                        self._logger.setLevel(
                            logging.getLevelName(logging.DEBUG))
                        self._logger.info('MgmtServer: set debug on')
                        ret = ({'debug': True, 'loglevel': 'DEBUG'}, None)
                    except Exception as ex:  # pylint: disable=broad-except
                        self._logger.error('MgmtServer: unknown error %s',
                                           ex.message)
                        ret = (None, RuntimeError(ex.message))
                elif msg['off']:
                    old_loglevel = self._conf.loglevel
                    try:
                        self._conf.set_param('debug', False)
                        self._logger.setLevel(old_loglevel)
                        self._logger.info('MgmtServer: set debug on')
                        ret = ({'debug': False, 'loglevel': old_loglevel},
                               None)
                    except Exception as ex:  # pylint: disable=broad-except
                        self._logger.error('MgmtServer: unknown error %s',
                                           ex.message)
                        ret = (None, RuntimeError(ex.message))
            elif msg['show']:
                op_dict = {
                    'version': VXFLD.VERSION,
                    'local': self._conf.src_ip,
                    'anycast': self._conf.svcnode_ip,
                    'peers': [ip_addr
                              for ip_addr, _ in self._conf.svcnode_peers]
                }
                if msg['detail']:
                    op_dict.update({
                        'data_port': self._conf.vxlan_port,
                        'ctrl_port': self._conf.vxfld_port
                    })
                ret = (op_dict, None)
            else:
                ret = (None, RuntimeError('Unknown request'))
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.error('MgmtServer: unknown error %s', ex.message)
            ret = (None, RuntimeError(ex.message))
        return ret

    def _run(self):
        """ Main method
        """
        self._conf.vxlan_listen_port = (
            self._conf.vxlan_listen_port or self._conf.vxlan_port
        )
        self._conf.vxlan_dest_port = (
            self._conf.vxlan_dest_port or self._conf.vxlan_port
        )
        # Install an anycast address on the loopback interface and associate a
        # cleanup method to be invoked on shutdown.
        if self._conf.install_svcnode_ip:
            if (self._conf.svcnode_ip ==
                    config.Config.CommonConfig.svcnode_ip.default):
                raise RuntimeError('Cannot install ANY addr on loopback IF')
            self.__add_ip_addr()
            atexit.register(self.__del_ip_addr)

        # Open the sockets
        try:
            if self._conf.enable_vxlan_listen:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Set SO_RCVBUF
                # NOTE(cfb): Setting SO_RCVBUF results in the size being 2x the
                # bytes passed to the setsockopt call. As such we pass it as
                # size/2.
                sock.setsockopt(socket.SOL_SOCKET,
                                socket.SO_RCVBUF,
                                self._conf.receive_queue / 2)
                sock.bind((self._conf.svcnode_ip,
                           self._conf.vxlan_listen_port))
                self._pool.spawn_n(self._serve, sock,
                                   self.__handle_vxlan_packet)
            if not self._conf.no_flood:
                # Don't create this if not flooding.  Then I can run non-root.
                self.__fsocketpool.create = (
                    lambda: socket.socket(socket.AF_INET,
                                          socket.SOCK_RAW,
                                          socket.IPPROTO_RAW)
                )
            isock = None
            for ip_addr, port in self.__vxfld_addresses:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Allows the RD and SND to bind to the same port if one of them
                # is using a wildcard address.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((ip_addr, port))
                if isock is None or ip_addr == self._conf.src_ip:
                    isock = sock
                self._pool.spawn_n(self._serve, sock, self.__handle_vxfld_msg)
            if isock is not None:
                self.__isocketpool.create = lambda: isock
            # Open a TCP socket for SND-SND communication.
            tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tsock.bind((self._conf.src_ip, self._conf.vxfld_port))
            tsock.listen(max(len(self._conf.svcnode_peers), 5))
            self._pool.spawn_n(self._serve_tcp, tsock,
                               self.__handle_vxfld_sync)
        except socket.error as ex:
            raise RuntimeError('opening receive and transmit sockets : %s' %
                               ex)

        # Sync the fdb from peer SNDs
        self._pool.spawn(self.__resync_fdb).link(self._stop_checker)

        # Periodically ageout stale FDB entries.
        next_ageout = 0
        while True:
            now = int(time.time())
            if now >= next_ageout:
                self.__fdb.ageout()
                next_ageout = now + self._conf.age_check
            eventlet.sleep(self._conf.age_check)

    def __add_ip_addr(self):
        """ Adds an IP address to the loopback interface.
        """
        try:
            self._logger.debug('Adding addr %s to loopback',
                               self._conf.svcnode_ip)
            cmd = '/bin/ip addr add %s/32 dev lo' % self._conf.svcnode_ip
            subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as ex:
            if ex.returncode == 2:
                self._logger.debug('Addr %s already installed',
                                   self._conf.svcnode_ip)
            else:
                # Log warning and keep on trucking.
                self._logger.warning('Failed to install addr %s on interface. '
                                     'out:%s', self._conf.svcnode_ip,
                                     ex.output, exc_info=True)

    def __del_ip_addr(self):
        """ Called by the exit handler to remove an IP address from the
        loopback interface.
        """
        try:
            self._logger.debug('Removing addr %s from loopback',
                               self._conf.svcnode_ip)
            cmd = '/bin/ip addr del %s/32 dev lo' % self._conf.svcnode_ip
            subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as ex:
            self._logger.warning('Failed to remove addr %s from interface. '
                                 'out:%s', self._conf.svcnode_ip,
                                 ex.output, exc_info=True)

    def __flood_vxlan_packet(self, pkt, addr, fwd_set):
        """ Floods VXLAN data packets to the fwd_set.
        :param pkt: VXLAN pkt
        :param addr: tuple composed of the sender's IP addr and source port
        :param fwd_set: set of ip addresses to which the packet should be
                        forwarded
        """
        srcip, srcport = addr
        udp_packet = dpkt.udp.UDP(sport=srcport,
                                  dport=self._conf.vxlan_dest_port,
                                  data=pkt)
        udp_packet.ulen = len(udp_packet)

        # It's quicker to replace the dstip for each VTEP rather than build
        # a new packet each time. As such start with a non-sensical dstip.
        ip_packet = dpkt.ip.IP(dst=socket.inet_aton(srcip),
                               src=socket.inet_aton(srcip),
                               ttl=64,
                               p=dpkt.ip.IP_PROTO_UDP,
                               data=udp_packet)
        ip_packet.len = len(ip_packet)
        ip_packet_str = str(ip_packet)
        # UDP checksum computation is optional for IPv4. It isn't being used,
        # so we should set it to zero.
        ip_packet_str = ip_packet_str[:26] + '\x00\x00' + ip_packet_str[28:]
        with self.__fsocketpool.item() as fsock:
            for dstip in fwd_set:
                self._logger.debug('Sending vxlan pkt from %s to %s',
                                   srcip, dstip)
                # Set the dstip in the packet directly to avoid re-packing the
                # whole packet each time.
                if dstip in self.__aton_cache:
                    dst = self.__aton_cache[dstip]
                else:
                    dst = socket.inet_aton(dstip)
                    self.__aton_cache[dstip] = dst
                ip_packet_str = ip_packet_str[:16] + dst + ip_packet_str[20:]
                try:
                    fsock.sendto(ip_packet_str, (dstip, 0))
                except Exception as ex:  # pylint: disable=broad-except
                    self._logger.error('Error sending flood packet to rd: %s',
                                       ex)

    def __handle_vxfld_msg(self, pkt, addr):
        """ Handles VXFLD messages.
        :param pkt: packet buffer
        :param addr: tuple composed of the sender's IP addr and port
        """
        # pylint: disable=no-member
        srcip, _ = addr
        try:
            pkt = VXFLD.Packet(pkt)
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.error('Unknown VXFLD packet received from %s: %s',
                               srcip, ex.message)
            return
        if pkt.type == VXFLD.MsgType.REFRESH:
            self.__handle_vxfld_refresh(pkt, addr)
        elif pkt.type == VXFLD.MsgType.PROXY:
            self.__handle_vxfld_proxy(pkt, addr)
        else:
            self._logger.error('Unknown VXFLD packet type %s received from %s',
                               pkt.type, srcip)

    def __handle_vxfld_proxy(self, pkt, addr):
        """ Handles vxsnd to vxsnd proxy messages.
        :param pkt: VXFLD pkt
        :param addr: tuple composed of the sender's IP addr and port
        """
        srcip, _ = addr
        self._logger.info('Proxy msg from %s', srcip)

        # Send messages to other proxies
        if pkt.data.ttl > 1:
            pkt.data.ttl -= 1
            pkt.data.add_proxy_ip(self._conf.proxy_id)
            if self._conf.vxfld_proxy_servers:
                # Check to see if we should only proxy packets from our local
                # area
                if self._conf.proxy_local_only:
                    if self._conf.area is not None:
                        if pkt.data.area == self._conf.area:
                            self._logger.debug('Forwarding pxy packet from '
                                               '%s, area %s', srcip,
                                               pkt.data.area)
                            self.__send_to_peers(
                                pkt, self._conf.vxfld_proxy_servers)
                    else:
                        self._logger.error('proxy_local_only requires option '
                                           '"area"')
                else:
                    self._logger.debug('Forwarding pxy packet from %s, area '
                                       '%s', srcip, pkt.data.area)
                    self.__send_to_peers(pkt, self._conf.vxfld_proxy_servers)

        # Flood messages to our local DB
        if self._conf.enable_flooding:
            # Only flood if the packet isn't local
            if self._conf.area is not None:
                if pkt.data.area != self._conf.area:
                    self.__handle_vxlan_packet(pkt.data.vxlan_pkt,
                                               (pkt.data.srcip,
                                                pkt.data.srcport),
                                               proxy=False,
                                               learn=False)
            else:
                self._logger.error('enable_flooding requires option "area"')

    def __handle_vxfld_refresh(self, pkt, addr):
        """ Handles a membership refresh message.
        :param pkt: VXFLD pkt
        :param addr: tuple composed of the sender's IP addr and port
        """
        srcip, _ = addr
        self._logger.debug('Refresh msg from %s. Holdtime: %s', srcip,
                           pkt.data.holdtime)
        response_type = pkt.data.response_type
        # Set the response type to None in the refresh message before
        # forwarding it on to peers.
        pkt.data.response_type = VXFLD.ResponseType.NONE
        # 0 is the default value of the field in the packet.
        identifier = getattr(pkt.data, 'identifier', 0) or None
        self.__update_fdb(pkt.data.vni_vteps, pkt.data.holdtime, identifier,
                          sync=False)
        if pkt.data.originator:
            if (self._conf.refresh_proxy_servers and
                    self._conf.vxfld_proxy_servers):
                # Send the packet to our proxy servers. Proxies may then
                # re-forward so don't change originator.
                self.__send_to_peers(pkt, self._conf.vxfld_proxy_servers)
            # Send on to all peers but set originator to 0 so that they do
            # not forward on.
            pkt.data.originator = False
            self.__send_to_peers(
                pkt, self.__vxfld_refresh_servers - self.__vxfld_addresses
            )
        # Check to see if the originator wants a refresh.
        if response_type:
            if response_type == VXFLD.ResponseType.REQUESTED:
                vteps = pkt.data.vni_vteps
            elif response_type == VXFLD.ResponseType.ALL:
                self._logger.info('Sending refresh response(all) to %s',
                                  srcip)
                vteps = self.__fdb
            else:
                self._logger.error('Unknown response_type requested from %s',
                                   srcip)
                return
            vni_dict = {}
            for vni in vteps:
                addr_set = self.__fdb.get_addrs(vni)
                if addr_set:
                    vni_dict[vni] = addr_set
            self.__send_refresh_pkt(addr, vni_dict,
                                    {'holdtime': self._conf.holdtime,
                                     'identifier': _Fdb.DEFAULT_ID,
                                     'version': pkt.version})

    def __handle_vxfld_sync(self, sock, addr):
        """ Handles vxsnd to vxsnd sync messages.
        :param sock: client socket
        :param addr: tuple composed of the sender's IP addr and port
        :returns: True if successful, False otherwise
        """
        # pylint: disable=no-member
        srcip, _ = addr
        try:
            self._logger.info('Sync packet from %s', srcip)
            pkt = VXFLD.Packet(
                b''.join(iter(lambda: sock.recv(self._conf.max_packet_size),
                              b''))
            )
            if pkt.data.vni_vteps:
                self._logger.info('Sync data from %s', srcip)
                for vni, iplist in pkt.data.vni_vteps.iteritems():
                    for ele in iplist:
                        ip_addr, holdtime, identifier = ele
                        self.__fdb.update(vni, ip_addr, holdtime, identifier)
            if pkt.data.response_type == VXFLD.ResponseType.ALL:
                self._logger.info('Sync request from %s', srcip)
                vteps = collections.defaultdict(list)
                now = int(time.time())
                for vni in self.__fdb:
                    for entry in self.__fdb.get(vni, now):
                        addr, holdtime, identifier = entry
                        if holdtime > 0:
                            vteps[vni].append((addr, holdtime, identifier))
                pkt.data.vni_vteps = vteps
                pkt_args = {'response_type': VXFLD.ResponseType.NONE}
                self.__send_sync_pkt(addr, pkt_args, sock=sock, vteps=vteps)
            return True
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.error('Failed to receive data from %s. %s', srcip, ex)
            if sock is not None:
                sock.close()
        return False

    def __handle_vxlan_packet(self, pkt, addr, proxy=True, learn=True):
        """ Handles VXLAN data packets.
        :param pkt: VXLAN pkt
        :param addr: tuple composed of the sender's IP addr and port
        :param proxy: set to True to forward the pkt to proxies
        :param learn: set to True to learn addresses from the pkt
        """
        srcip, _ = addr
        try:
            vxlan_pkt = VXLAN(pkt)
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.error('Unknown VXLAN packet received from %s: %s',
                               srcip, ex.message)
            return

        if not vxlan_pkt.i:
            return

        # Send messages to other proxies
        if proxy and self._conf.vxfld_proxy_servers:
            self.__send_vxfld_proxy(pkt, addr)

        fwd_list = self.__fdb.get(vxlan_pkt.vni)
        in_fdb = False
        refresh = True
        if fwd_list:
            new_fwd_set = set()
            for dstip, _, identifier in fwd_list:
                if dstip == srcip:
                    in_fdb = True
                    refresh &= identifier == _Fdb.DEFAULT_ID
                    continue
                new_fwd_set.add(dstip)
            # Refresh the hold time if the only entry in the fdb for a
            # <vni, addr> is one that was added by the SND.
            if in_fdb and refresh:
                self._logger.debug('Refreshing ip %s, vni %d from '
                                   'VXLAN pkt', srcip, vxlan_pkt.vni)
                self.__fdb.refresh(vxlan_pkt.vni,
                                   srcip,
                                   self._conf.holdtime)
            if not self._conf.no_flood:
                self.__flood_vxlan_packet(pkt, addr, new_fwd_set)
        if not in_fdb and learn:
            # Add the <vni, srcip> to the fdb and tell peers about it.
            self._logger.info('Learning ip %s, vni %d from VXLAN pkt', srcip,
                              vxlan_pkt.vni)
            try:
                self.__update_fdb({vxlan_pkt.vni: {srcip}},
                                  self._conf.holdtime)
            except Exception as ex:  # pylint: disable=broad-except
                self._logger.debug('Failed to update fdb. %s', ex)

    def __resync_fdb(self):
        """ Resyncs the FDB from proxy and/or refresh servers.
        """
        while True:
            targets = set()
            # First see if we need to sync from proxies
            if (self._conf.sync_from_proxy and
                    self._conf.vxfld_proxy_servers):
                if (len(self._conf.vxfld_proxy_servers) <=
                        self._conf.sync_targets):
                    targets.update(self._conf.vxfld_proxy_servers)
                else:
                    targets.update(sample(self._conf.vxfld_proxy_servers,
                                          self._conf.sync_targets))
            needed = self._conf.sync_targets - len(targets)
            if needed > 0 and self.__vxfld_refresh_servers:
                possible = (
                    self.__vxfld_refresh_servers - self.__vxfld_addresses
                )
                if len(possible) <= needed:
                    targets.update(possible)
                else:
                    targets.update(sample(possible, needed))
            if not targets:
                break
            self._logger.info('Requesting fdb sync from %s', targets)
            pkt_args = {'response_type': VXFLD.ResponseType.ALL}
            try:
                for addr in targets:
                    sock = self.__send_sync_pkt(addr, pkt_args)
                    assert self.__handle_vxfld_sync(sock, addr)
                    sock.close()
            except Exception:  # pylint: disable=broad-except
                eventlet.sleep(10)
            else:
                break

    def __send_refresh_pkt(self, addr, vteps, pkt_args):
        """ Sends a VXLAN refresh pkt. to the source addr.
        :param addr: tuple composed of the sender's IP addr and port
        :param vteps: maps VNIs to IP addresses
        :type vteps: dict[int, set(str) | list(str)]
        :param pkt_args: maps inner packet attributes to their values
        """
        # pylint: disable=missing-docstring
        def send_pkt(pkt_in, addr_in):
            with self.__isocketpool.item() as isock:
                try:
                    isock.sendto(str(pkt_in), addr_in)
                except Exception as ex:  # pylint: disable=broad-except
                    # Socket not ready, buffer overflow etc.
                    self._logger.error('Failed to send vxfld pkt reply: %s',
                                       ex)
        packet_count = 0
        holdtime = pkt_args.get('holdtime', self._conf.holdtime)
        identifier = pkt_args.get('identifier', _Fdb.DEFAULT_ID)
        version = pkt_args.get('version', VXFLD.VERSION)
        vxfld_pkt = None
        for vni, msgdata in vteps.iteritems():
            # Limit the refresh message size to max_packet_size.
            if (vxfld_pkt is None or
                    VXFLD.BASE_PKT_SIZE + len(vxfld_pkt) +
                    vxfld_pkt.data.ipstr_len(vni, msgdata) >=
                    self._conf.max_packet_size):
                if vxfld_pkt is not None:
                    send_pkt(vxfld_pkt, addr)
                    packet_count += 1
                    if packet_count % self.__VXFLD_PKT_BURST_SIZE == 0:
                        eventlet.sleep(1)
                # Set originator to 0 so peers don't forward on.
                vxfld_pkt = (
                    VXFLD.Packet(type=VXFLD.MsgType.REFRESH,
                                 version=version,
                                 inner={'holdtime': holdtime,
                                        'originator': False,
                                        'response_type':
                                            VXFLD.ResponseType.NONE,
                                        'identifier': identifier})
                )
            vxfld_pkt.data.vni_vteps = {vni: msgdata}
        if vxfld_pkt is not None and vxfld_pkt.data.vni_vteps:
            send_pkt(vxfld_pkt, addr)

    def __send_sync_pkt(self, addr, pkt_args, sock=None, vteps=None):
        """ Generates and sends a VXFLD sync pkt. to peer SNDs.
        :param addr: tuple composed of the recipients' IP addr and port
        :param pkt_args: maps inner packet attributes to their values
        :param sock: socket object
        :param vteps: maps VNIs to tuples composed of a VTEP's IP address,
                      holdtime and node identifier
        :type vteps: dict[int, (str, int, int)]
        :returns: a socket object
        :raises: socket.error
        """
        response_type = pkt_args.get('response_type', VXFLD.ResponseType.NONE)
        vxfld_pkt = VXFLD.Packet(type=VXFLD.MsgType.SYNC,
                                 inner={'response_type': response_type})
        if vteps is not None:
            vxfld_pkt.data.vni_vteps = vteps
        try:
            if sock is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(addr)
            sock.sendall(str(vxfld_pkt))
            sock.shutdown(socket.SHUT_WR)
            return sock
        except socket.error as ex:
            # Socket not ready, buffer overflow etc.
            if sock is not None:
                sock.close()
            self._logger.error('Failed to send sync pkt: %s', ex)
            raise

    def __send_to_peers(self, pkt, servers):
        """ Sends a pkt. to one or more servers.
        :param pkt: VXFLD pkt
        :param servers: set of tuples composed of the recipients' IP address
                        and port
        """
        with self.__isocketpool.item() as isock:
            for ip_addr, port in servers - self.__vxfld_addresses:
                if (pkt.type == VXFLD.MsgType.PROXY and
                        ip_addr in pkt.data.proxy_ips):
                    continue
                try:
                    isock.sendto(str(pkt), (ip_addr, port))
                except Exception:  # pylint: disable=broad-except
                    self._logger.exception('Error sending update to peer snd '
                                           '%s:%d', ip_addr, port)

    def __send_vxfld_proxy(self, vxlan_pkt, addr):
        """ Generates and sends a VXFLD proxy packet to peer SNDs.
        :param vxlan_pkt: VXLAN data packet
        :param addr: tuple composed of the sender's IP addr and port
        """
        if self._conf.area is None:
            self._logger.error('Sending proxy packets requires config option '
                               '"area"')
            return
        srcip, srcport = addr
        pkt = VXFLD.Packet(type=VXFLD.MsgType.PROXY,
                           version=VXFLD.VERSION,
                           inner={'area': self._conf.area,
                                  'srcport': srcport})
        pkt.data.srcip = srcip
        pkt.data.vxlan_pkt = vxlan_pkt
        pkt.data.add_proxy_ip(self._conf.proxy_id)
        self._logger.debug('Sending proxy packet from %s', srcip)
        self.__send_to_peers(pkt, self._conf.vxfld_proxy_servers)

    def __update_fdb(self, vni_dict, holdtime, identifier=_Fdb.DEFAULT_ID,
                     sync=True):
        """ Updates the SND's FDB and sends a sync message to its peers.
        :param vni_dict: maps VNIs to IP addresses
        :type vni_dict: dict[int, set[str]]
        :param holdtime: set to non-zero to add entries and 0 to remove them
        :param identifier: identifies the source of an update. DEFAULT_ID is
                           used when the source is the SND
        :param sync: set to True to send a sync message to peers
        :raises: socket.error when sync=True
        """
        vteps = collections.defaultdict(list)
        for vni, ip_addr_set in vni_dict.iteritems():
            for ip_addr in ip_addr_set:
                if holdtime:
                    self.__fdb.update(vni, ip_addr, holdtime, identifier)
                else:
                    self.__fdb.remove(vni, ip_addr, identifier)
                vteps[vni].append((ip_addr, holdtime, identifier))
        refresh_addrs = self.__vxfld_refresh_servers
        if self._conf.refresh_proxy_servers:
            refresh_addrs.update(self._conf.vxfld_proxy_servers)
        if sync and refresh_addrs:
            pkt_args = {'response_type': VXFLD.ResponseType.NONE}
            for addr in refresh_addrs - self.__vxfld_addresses:
                sock = self.__send_sync_pkt(addr, pkt_args, vteps=vteps)
                sock.close()


def main():
    """ Main method
    """
    prsr = utils.common_parser(NODE_TYPE)
    # For running non-sudo. Disables bind to raw socket.
    prsr.add_argument('-R', '--no-flood', action='store_true',
                      help='Turn off flooding')
    args = prsr.parse_args()
    conf = utils.load_configuration(NODE_TYPE, args)
    vxsnd_inst = _Vxsnd(conf)
    return vxsnd_inst.run()
