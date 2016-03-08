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
""" This module provides classes used by the VXLAN Registration Daemon (vxrd).
"""
import atexit
import collections
import errno
import itertools
import operator
import re
import socket
import subprocess
import tempfile
import time

import eventlet
import eventlet.pools

from vxfld.common import config, netlink, service, utils
from vxfld.common.enums import NodeType, OperState
from vxfld.pkt import vxfld as VXFLD

_IP_ADDR_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
NODE_TYPE = NodeType.VXRD


class _BridgeUtils(object):
    """ HER: provides methods to read from or write to the bridge fdb table.
    """
    __BRPORT_MAC_ADDR = '00:00:00:00:00:00'
    __BRPORT_REGEX = re.compile(
        r'^{0}'
        r'(?=.*dst\s+(?P<dst_addr>{1}))'
        r'(?=.*dev\s+(?P<dev_name>\S+))'.format(__BRPORT_MAC_ADDR,
                                                _IP_ADDR_REGEX)
    )
    __CMD_PATH = '/sbin/bridge'
    __MAX_CMDS_PER_BATCH = 2000
    __BATCH_MODE = None

    # Bridge fdb operations.
    ADD = 'append'
    DEL = 'del'

    def __init__(self, force=True):
        self.__entries = []
        self.__force = force

    def __enter__(self):
        self.__entries = []
        return self

    def __exit__(self, *args):
        if not self.set_hrep_macs():
            raise OSError('Failed to update bridge fdb')

    @classmethod
    def __batch_supported(cls):
        """ Checks to see if -batch is supported by the bridge cmd. Required
        to get vxrd, with head_rep, working in ubuntu < 16.04
        :return: True if batch mode is supported, False otherwise
        """
        if cls.__BATCH_MODE is not None:
            return cls.__BATCH_MODE
        else:
            cmd = '%s help' % cls.__CMD_PATH
            try:
                bridgecmd = subprocess.Popen(cmd.split(),
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT)
                output = bridgecmd.communicate()[0]
            except Exception:  # pylint: disable=broad-except
                return False
            cls.__BATCH_MODE = '-batch' in output
            return cls.__BATCH_MODE

    def add_entry(self, operation, dev_name, ip_address):
        """ Appends an entry to the list of bridge fdb commands.
        :param operation: can be one of ADD and DEL
        :param dev_name: device name
        :param ip_address: peer IP address
        """
        if operation not in (self.ADD, self.DEL):
            raise RuntimeError('Invalid operation %s' % operation)
        self.__entries.append('fdb %s %s dev %s dst %s\n' % (
            operation, self.__BRPORT_MAC_ADDR, dev_name, ip_address
        ))

    @classmethod
    def get_hrep_macs(cls):
        """ Parses the output of 'bridge fdb show' and returns the results.
        :returns: maps device names to IP addresses
        :rtype: dict[str, set(str)]
        :raises OSError: when the operation fails
        """
        dev_map = collections.defaultdict(set)
        cmd = (
            '%s fdb show | /bin/grep %s ; ( echo $PIPESTATUS )' % (
                cls.__CMD_PATH, cls.__BRPORT_MAC_ADDR
            )
        )
        try:
            # shell=True is being passed to subprocess because eventlet's
            # version doesn't support piping of data between processes.
            # This is because eventlet assumes that the stdout file
            # descriptor will be used from within the Python process, and
            # it helpfully marks it as non-blocking so methods like
            # communicate won't block. This results in the process on the
            # other end of the pipe getting an -EAGAIN when it tries to
            # read from what it thinks is a blocking socket.
            # See http://russ.garrett.co.uk/2011/12/16/
            # green-threads-and-pipes-in-python/ for details.
            bridge = subprocess.Popen(cmd,
                                      stdout=subprocess.PIPE,
                                      shell=True)
        except Exception as ex:  # pylint: disable=broad-except
            raise OSError('Command failed. out:%s' % ex)
        for line in iter(bridge.stdout.readline, b''):
            pat_match = cls.__BRPORT_REGEX.match(line.rstrip())
            if pat_match is not None:
                pat_dict = pat_match.groupdict()
                dev_map[pat_dict['dev_name']].add(pat_dict['dst_addr'])
        if bridge.wait() == 0:
            return dev_map
        else:
            raise OSError('%s returned non-zero exit code' % cmd)

    def set_hrep_macs(self):
        """ Updates the bridge fdb table by executing the bridge command with
        the temporary batch file as input.
        :returns: True if successful, False otherwise
        :raises OSError: when the operation fails
        """
        status = True
        if self.__batch_supported():
            for idx in range(0, len(self.__entries),
                             self.__MAX_CMDS_PER_BATCH):
                with tempfile.NamedTemporaryFile('w',
                                                 prefix='vxrd_tmp') as tmpf:
                    cmd = '%s -force -batch %s' % (self.__CMD_PATH, tmpf.name)
                    tmpf.writelines(
                        self.__entries[idx:idx + self.__MAX_CMDS_PER_BATCH]
                    )
                    tmpf.flush()
                    try:
                        subprocess.check_output(cmd.split(),
                                                stderr=subprocess.STDOUT)
                    except subprocess.CalledProcessError:
                        status &= False
                        if not self.__force:
                            return False
        else:
            for line in self.__entries:
                cmd = '%s -force %s' % (self.__CMD_PATH, line)
                try:
                    subprocess.check_output(cmd.split(),
                                            stderr=subprocess.STDOUT)
                except subprocess.CalledProcessError:
                    status &= False
                    if not self.__force:
                        return False
        return status


class _DeviceConfig(object):
    """ VXLAN device config/runtime state.
    """
    # pylint: disable=too-few-public-methods
    class InvalidConfig(Exception):
        """ Indicates an invalid configuration.
        """
        pass

    class NonOperational(Exception):
        """ Indicates a non operational device.
        """
        pass

    def __init__(self, dev_name, localip, svcnodeip, hrep_addrs=None):
        self.dev_name = dev_name
        self.localip = localip
        self.svcnodeip = svcnodeip
        self.hrep_addrs = hrep_addrs or set()

    def __eq__(self, other):
        return (isinstance(other, _DeviceConfig) and
                self.localip == other.localip and
                self.svcnodeip == other.svcnodeip and
                self.dev_name == other.dev_name)

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return ('%s(dev_name=%s, localip=%s, svcnodeip=%s, hrep_addrs=%s)' %
                (self.__class__.__name__, self.dev_name, self.localip,
                 self.svcnodeip, self.hrep_addrs))


class _Vxrd(service.Vxfld):
    """ Main class that provides methods used by the VXLAN Registration Daemon.
    """
    __VXLAN_REGEX = re.compile(
        r'^\d+: (?P<dev_name>\S+):'
        r'(?=.*state\s+(?P<state>\S+))'
        r'(?=.*vxlan\s+id\s+(?P<vni>\d+))'
        r'(?=.*dstport\s+(?P<dstport>\d+))?'
        r'(?=.*local\s+(?P<local_addr>{0}))?'
        r'(?=.*(?:svcnode|remote)\s+(?P<sn_addr>{0}))?'.format(_IP_ADDR_REGEX)
    )

    def __init__(self, conf):
        super(_Vxrd, self).__init__(conf)
        self.__vni_config = {}    # vni_config[vni] = DeviceConfig
        self.__peerdb = {}        # peerdb[vni] = {ip, ...}
        self.__next_refresh = 0
        self.__next_sync_check = 0
        self.__nlmonitor = netlink.Netlink(
            {netlink.Netlink.NEWLINK: self.__add_iface,
             netlink.Netlink.DELLINK: self.__del_iface},
            self._logger,
            pool=self._pool
        )
        # socket for RD-SND communication.
        self.__sockpool = eventlet.pools.Pool(max_size=1)
        # Send a message to the SND and flush bridge fdb entries when the
        # process exits.
        atexit.register(self.__remove_vnis)
        if self._conf.head_rep:
            # HER: The RD limits the pool size to 1 to avoid parallel updates
            # to the kernel state.
            self.__herpool = eventlet.GreenPool(size=1)
            # Used to keep track of when the last response was received from
            # the SND.
            self.__last_response = None
            # Frequency at which the kernel state should be synced with the
            # peerdb.
            self.__sync_ready = True

    def _process(self, msg):
        """ Process requests from a mgmt. client.
        :returns: result object and Exception. Latter would be None if
                  everything is good
        """
        # pylint: disable=too-many-branches,too-many-return-statements
        try:
            if msg['vxlans']:
                if msg['hrep'] and not self._conf.head_rep:
                    return None, None
                elif msg['<vni>']:
                    vni = int(msg['<vni>'])
                    return {vni: self.__vni_config[vni]}, None
                else:
                    return self.__vni_config, None
            elif msg['peers']:
                if self._conf.head_rep:
                    if msg['<vni>']:
                        vni = int(msg['<vni>'])
                        return {vni: self.__peerdb[vni]}, None
                    else:
                        return self.__peerdb, None
                else:
                    return None, None
            elif msg['get'] and msg['config']:
                if msg['<parameter>'] is not None:
                    parameter = msg['<parameter>']
                    paramaters = self._conf.get_params()
                    if parameter in paramaters:
                        value = paramaters.get(parameter, None)
                        return {parameter: value}, None
                    else:
                        return None, RuntimeError('Unknown parameter')
                else:
                    return self._conf.get_params(), None
            elif msg['show']:
                return {
                    'version': VXFLD.VERSION,
                    'src_ip': self._conf.src_ip,
                    'snd_ip': self._conf.svcnode_ip,
                    'head_rep': self._conf.head_rep
                }, None
            else:
                return None, RuntimeError('Unknown request')
        except Exception:  # pylint: disable=broad-except
            return None, RuntimeError('Bad message')

    def _run(self):
        """ Periodically sends a registration message to the SND. Usually at
        regular time intervals but may be accelerated if membership has
        changed.
        """
        # Open a socket for sending refresh msgs.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Couple of reasons for doing this
        # a) allows the RD and SND to bind to the same port if one of them
        #    is using a wildcard address.
        # b) prevents EADDRINUSE by allowing the RD to rebind to the
        #    same address/port when it is restarted.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self._conf.src_ip, self._conf.vxfld_port))
        except socket.error as ex:
            raise RuntimeError('opening transmit socket : %s' % ex)
        self.__sockpool.create = lambda: sock

        # Initialize the vni_config db after binding the socket used for
        # SND-RD communication.
        self.__initialize_db()

        if self._conf.head_rep:
            # Spawn a thread for receiving refresh msgs from the SND.
            self._pool.spawn_n(self._serve, sock, self.__handle_vxfld_msg,
                               pool=self.__herpool)

        # Start the netlink dispatcher
        self.__nlmonitor.run().link(self._stop_checker)

        while True:
            now = int(time.time())
            if now >= self.__next_refresh:
                self.__next_refresh = (
                    now + self._conf.holdtime / self._conf.refresh_rate
                )
                self.__send_refresh(self.__vni_config, self._conf.holdtime)
            if self._conf.head_rep:
                if now >= self.__next_sync_check:
                    # HER: Ensure that the peerdb and HREP entries are in sync.
                    if self.__sync_ready:
                        self.__sync_ready = False
                        hergt = self.__herpool.spawn(self.__sync_peerdb)
                        hergt.link(self._stop_checker)
                        self.__next_sync_check = (
                            now + self._conf.config_check_rate
                        )
                    else:
                        # Try again in the next cycle
                        self.__next_sync_check = now + 1
                # HER: Flush the peerdb and HREP MAC entries if the RD
                # hasn't heard from the SND in more than holdtime seconds.
                if (self.__vni_config and self.__last_response is not None and
                        (now - self.__last_response) > self._conf.holdtime):
                    self._logger.warning('Lost contact with SND. Cleaning '
                                         'up...')
                    self.__last_response = None
                    self.__remove_vnis(self.__vni_config)
            eventlet.sleep(1)

    def __add_iface(self, dev_config):
        """ Adds an interface to the FDB and sends a refresh message to the
        SND.
        :param dev_config: VxlanDevice object
        :returns: VXLAN device ifindex
        """
        try:
            new = self.__new_vxlan_device(dev_config.dev_name,
                                          dev_config.localip,
                                          dev_config.remoteip,
                                          dev_config.state)
        except _DeviceConfig.InvalidConfig as ex:
            self._logger.warning(str(ex))
            self.__del_iface(dev_config, update=True)
        except _DeviceConfig.NonOperational as ex:
            self._logger.debug(str(ex))
            self.__del_iface(dev_config, update=True)
        else:
            now = int(time.time())
            vni = int(dev_config.vni)
            old = self.__vni_config.get(vni, None)
            if old is None:
                # If this is a new VXLAN device, then schedule the next sync
                # check in 2 seconds
                self.__next_sync_check = now + 2
            if old != new:
                self._logger.info('add_iface: %s', dev_config)
                self.__vni_config[vni] = new
                # VXLAN config has changed. Send an update to the SND.
                self.__send_refresh({vni: self.__vni_config[vni]},
                                    self._conf.holdtime)
        return dev_config.ifindex

    def __del_iface(self, dev_config, update=False):
        """ Removes an interface from the FDB. Notifies the SND by sending
        a refresh message with holdtime set to 0.
        :param dev_config: VxlanDevice object
        :returns: VXLAN device ifindex
        """
        vni = int(dev_config.vni)
        if vni in self.__vni_config:
            if update:
                self._logger.info('del_iface(ADDLINK): %s', dev_config)
                self.__remove_vnis({vni: self.__vni_config[vni]})
            else:
                self._logger.info('del_iface(DELLINK): %s', dev_config)
                self.__peerdb.pop(vni, None)
                self.__send_refresh({vni: self.__vni_config[vni]}, 0)
            self.__vni_config.pop(vni)
        return dev_config.ifindex

    def __get_vxlan_config(self):
        """ Parses the output of 'ip link show' and 'bridge fdb show' (if HER
        is enabled) and returns the result.
        :returns: dictionary mapping a VNI to a DeviceConfig object if
                  successful, otherwise None
        :rtype: dict[int, DeviceConfig] | None
        """
        vni_config = {}
        dev_map = collections.defaultdict(set)
        if self._conf.head_rep:
            try:
                dev_map = _BridgeUtils.get_hrep_macs()
            except OSError as ex:
                self._logger.debug(str(ex))
                return None
        cmd = '/bin/ip -d -o link show'
        try:
            iplinkshow = subprocess.Popen(cmd.split(),
                                          stdout=subprocess.PIPE)
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.warning('Command failed. out:%s', ex)
            return None
        for line in iter(iplinkshow.stdout.readline, b''):
            pat_match = self.__VXLAN_REGEX.match(line.rstrip())
            if pat_match is not None:
                match_dict = pat_match.groupdict()
                vni = int(match_dict['vni'])
                try:
                    vni_config[vni] = self.__new_vxlan_device(
                        match_dict['dev_name'],
                        match_dict['local_addr'],
                        match_dict['sn_addr'],
                        match_dict['state']
                    )
                except _DeviceConfig.InvalidConfig as ex:
                    self._logger.warning(str(ex))
                except _DeviceConfig.NonOperational as ex:
                    self._logger.debug(str(ex))
                else:
                    vni_config[vni].hrep_addrs = (
                        dev_map[match_dict['dev_name']]
                    )
        if iplinkshow.wait() == 0:
            return vni_config
        else:
            self._logger.error('%s returned non-zero exit code', cmd)
            return None

    def __handle_vxfld_msg(self, pkt, addr):
        """ HER: Handles a VXFLD message.
        :param pkt: socket buffer
        :param addr: tuple composed of the sender's address and port
        """
        # pylint: disable=no-member
        srcip, _ = addr
        self.__last_response = int(time.time())
        try:
            vxfld_pkt = VXFLD.Packet(pkt)
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.error('Unknown VXFLD packet received from %s: %s',
                               srcip, ex.message)
            return
        refresh_pkt = vxfld_pkt.data
        if vxfld_pkt.type != VXFLD.MsgType.REFRESH:
            self._logger.warning('Unexpected vxfld pkt of type %d',
                                 vxfld_pkt.type)
            return
        self._logger.info('Refresh msg from %s', srcip)
        self._logger.debug('Vteps %s', refresh_pkt.vni_vteps)
        # Compute the list of updated VNIs
        updated_vnis = {
            vni: set(iplist)
            for vni, iplist in refresh_pkt.vni_vteps.iteritems()
            if set(iplist) != self.__peerdb.get(vni, set())
        }
        if updated_vnis:
            self.__update_peerdb(updated_vnis)

    def __initialize_db(self):
        """ Initializes the RD's database and binds the netlink socket.
        Also invoked when socket.recv returns ENOBUFS to rebind the netlink
        socket.
        """
        if self.__nlmonitor.socket is not None:
            self._logger.info('Rebinding netlink socket')
        self.__nlmonitor.bind()
        self._pool.spawn_n(self._serve,
                           self.__nlmonitor.socket,
                           self.__nlmonitor.handle_netlink_msg,
                           bufsize=netlink.Netlink.NLSOCK_BYTES,
                           err_cbs={errno.ENOBUFS: self.__initialize_db})
        old, self.__vni_config = self.__vni_config, None
        while self.__vni_config is None:
            self.__vni_config = self.__get_vxlan_config()
        if old and old != self.__vni_config:
            removed = {vni: vni_config
                       for vni, vni_config in old.iteritems()
                       if vni not in self.__vni_config}
            self.__remove_vnis(removed)
        # Send a refresh message to the SND with the current config.
        # Schedule another refresh in 1 sec just in case the UDP
        # msg is lost.
        self.__send_refresh(self.__vni_config, self._conf.holdtime)
        self.__next_refresh = int(time.time()) + 1

    def __new_vxlan_device(self, dev_name, localip, svcnodeip, state):
        """ Returns a DeviceConfig object after validating inputs to this
        method.
        :param dev_name: device name
        :param localip: local IP address
        :param svcnodeip: svcnode IP address
        :param state: operational state
        :return: DeviceConfig object if successful, otherwise raises
                 an Exception.
        :raises: DeviceConfig.InvalidConfig or DeviceConfig.NonOperational
        """
        if (localip is None or
                (not self._conf.head_rep and svcnodeip is None)):
            raise _DeviceConfig.InvalidConfig(
                'Invalid configuration detected for device %s. localip: %s, '
                'svcnodeip: %s, head_rep: %s' % (dev_name, localip, svcnodeip,
                                                 self._conf.head_rep)
            )
        if state not in (OperState.OPERSTATE_STR[OperState.IF_OPER_UP],
                         OperState.OPERSTATE_STR[OperState.IF_OPER_UNKNOWN]):
            raise _DeviceConfig.NonOperational(
                'Device %s with state %s is not operational' % (dev_name,
                                                                state)
            )
        # Use the VTEP's svcnode IP in the kernel if it's missing in the
        # daemon configuration.
        svcnode_ip = self._conf.svcnode_ip
        if (svcnode_ip == config.Config.CommonConfig.svcnode_ip.default and
                svcnodeip is not None):
            svcnode_ip = svcnodeip
        # got vni, local and sn.  Add to dict
        return _DeviceConfig(dev_name=dev_name, localip=localip,
                             svcnodeip=svcnode_ip)

    def __remove_vnis(self, vnis=None):
        """ Sends a refresh message to the SND with the holdtime set to 0 for
        VNIs passed to this method (defaults to all VNIs).
        Purges HREP addresses from the bridge fdb table when HER is enabled.
        :param vnis: maps VNIs to DeviceConfig objects
        :type vnis: dict[int, DeviceConfig]
        """
        vnis = vnis or self.__vni_config
        self.__send_refresh(vnis, 0)
        if self._conf.head_rep:
            self.__herpool.spawn(self.__update_peerdb,
                                 {vni: set() for vni in vnis
                                  if self.__peerdb.get(vni, set())}).wait()

    def __send_refresh(self, vni_data, hold):
        """ Sends a refresh message to the SND.
        :param vni_data: maps VNIs to DeviceConfig objects
        :type vni_data: dict[int, DeviceConfig]
        :param hold: packet holdtime
        :returns: True if successful, False otherwise.
        """
        # Build the right data structure for the message
        # need msg_data as {svcnode: {vni: [local]}}
        pkt_pile = eventlet.GreenPile(self._pool)
        for svcnode, grouper in itertools.groupby(
                vni_data, lambda k: vni_data.get(k).svcnodeip):
            vxfld_pkt = None
            for vni in grouper:
                addrs = [vni_data.get(vni).localip]
                # Limit the refresh message to max_packet_size.
                if (vxfld_pkt is None or
                        VXFLD.BASE_PKT_SIZE + len(vxfld_pkt) +
                        vxfld_pkt.data.ipstr_len(vni, addrs) >=
                        self._conf.max_packet_size):
                    if vxfld_pkt is not None:
                        pkt_pile.spawn(self.__send_vxfld_pkt, vxfld_pkt,
                                       svcnode)
                    vxfld_pkt = (
                        VXFLD.Packet(type=VXFLD.MsgType.REFRESH,
                                     version=VXFLD.VERSION,
                                     inner={'holdtime': hold,
                                            'originator': True,
                                            'identifier':
                                                self._conf.node_id})
                    )
                    # We don't require an acknowledgement for delete messages.
                    if self._conf.head_rep and hold != 0:
                        vxfld_pkt.data.response_type = (
                            VXFLD.ResponseType.REQUESTED
                        )
                vxfld_pkt.data.vni_vteps = {vni: addrs}
            if vxfld_pkt is not None and vxfld_pkt.data.vni_vteps:
                pkt_pile.spawn(self.__send_vxfld_pkt, vxfld_pkt, svcnode)
        return not pkt_pile.used or reduce(operator.and_, pkt_pile, True)

    def __send_vxfld_pkt(self, pkt, addr):
        """ Sends a VXFLD refresh packet to the SND.
        :param pkt: packet buffer
        :param addr: tuple composed of the svcnode's addr and port
        :returns: True if successful, False otherwise.
        """
        self._logger.info('Sending to %s: Holdtime: %s', addr,
                          pkt.data.holdtime)
        self._logger.debug('Vteps %s', pkt.data.vni_vteps)
        with self.__sockpool.item() as sock:
            try:
                sock.sendto(str(pkt), (addr, self._conf.vxfld_port))
                return True
            except Exception as ex:  # pylint: disable=broad-except
                self._logger.error('Error sending refresh packet: %s', ex)
            return False

    def __sync_peerdb(self):
        """ HER: Maintain sync between the daemon and kernel state by updating
        the bridge fdb table.
        """
        try:
            dev_map = _BridgeUtils.get_hrep_macs()
        except OSError as ex:
            self._logger.debug(str(ex))
        else:
            updated_vnis = {}
            for vni, vni_config in self.__vni_config.iteritems():
                peerips = self.__peerdb.get(vni, set())
                myaddr = {vni_config.localip}
                dev_name = vni_config.dev_name
                vni_config.hrep_addrs = dev_map[dev_name]
                dev_map.pop(dev_name, None)
                if vni_config.hrep_addrs ^ peerips - myaddr:
                    updated_vnis[vni] = peerips
            if dev_map:
                # Flush HREP addresses for non-operational devices from the
                # bridge fdb table.
                try:
                    with _BridgeUtils() as bridge_obj:
                        for dev_name, ip_addrs in dev_map.iteritems():
                            for ip_addr in ip_addrs:
                                bridge_obj.add_entry(_BridgeUtils.DEL,
                                                     dev_name,
                                                     ip_addr)
                except OSError as ex:
                    self._logger.debug(str(ex))
            if updated_vnis:
                self.__update_peerdb(updated_vnis)
        self.__sync_ready = True

    def __update_peerdb(self, updated_vnis):
        """ HER: Updates the peerdb and corresponding bridge fdb entries.
        :param updated_vnis: maps VNIs to peer IP addresses
        :type updated_vnis: dict[int, set[str]]
        :returns: True if successful, False otherwise.
        """
        try:
            with _BridgeUtils() as bridge_obj:
                for vni, ipset in updated_vnis.iteritems():
                    if vni not in self.__vni_config:
                        continue
                    dev_name = self.__vni_config[vni].dev_name
                    my_addr = self.__vni_config[vni].localip
                    cur_addrs = self.__vni_config[vni].hrep_addrs
                    if ipset and my_addr not in ipset:
                        # should not happen if SND is behaving properly
                        self._logger.debug('Localip %s not found in peer '
                                           'iplist %s for VNI %d.', my_addr,
                                           ipset, vni)
                        continue
                    # We update HREP addresses assuming that the update to the
                    # bridge fdb will succeed. Discrepancies between kernel
                    # and daemon state will be handled during the next config
                    # check cycle.
                    self.__vni_config[vni].hrep_addrs = ipset - {my_addr}
                    self._logger.debug('Updating peer list for VTEP %s. new: '
                                       '%s. peerdb: %s, hrep: %s, myaddr: %s',
                                       dev_name, ipset,
                                       self.__peerdb.get(vni, set()),
                                       cur_addrs, my_addr)
                    if ipset:
                        self.__peerdb[vni] = ipset
                    else:
                        self.__peerdb.pop(vni, None)
                    for operation, peerips in \
                        ((_BridgeUtils.DEL, cur_addrs - (ipset - {my_addr})),
                         (_BridgeUtils.ADD, ipset - cur_addrs - {my_addr})):
                        for peerip in peerips:
                            bridge_obj.add_entry(operation, dev_name, peerip)
        except OSError as ex:
            self._logger.debug(str(ex))
            return False
        return True


def main():
    """ Main method
    """
    prsr = utils.common_parser(NODE_TYPE)
    args = prsr.parse_args()
    conf = utils.load_configuration(NODE_TYPE, args)
    vxrd_inst = _Vxrd(conf)
    return vxrd_inst.run()
