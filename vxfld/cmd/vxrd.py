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
import collections
import itertools
import re
import socket
import subprocess
import tempfile
import time

import eventlet
from eventlet.event import Event

from vxfld.common import config, service, utils
from vxfld.common.enums import NodeType
from vxfld.pkt import vxfld as VXFLD

_NODE_NAME = 'vxrd'
NODE_TYPE = NodeType.VXRD


class _DeviceConfig(object):
    """ Used by the RD to track the VTEP configuration state.
    """
    # pylint: disable=too-few-public-methods
    def __init__(self, dev_name, localip, svcnodeip, hrep_addrs=None):
        self.dev_name = dev_name
        self.localip = localip
        self.svcnodeip = svcnodeip
        self.hrep_addrs = hrep_addrs

    def __eq__(self, other):
        return (isinstance(other, _DeviceConfig) and
                self.localip == other.localip and
                self.svcnodeip == other.svcnodeip and
                self.dev_name == other.dev_name and
                self.hrep_addrs == other.hrep_addrs)

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return ('%s(dev_name=%s, localip=%s, svcnodeip=%s, hrep_addrs=%s)' %
                (self.__class__.__name__, self.dev_name, self.localip,
                 self.svcnodeip, self.hrep_addrs))


class _Vxrd(service.Vxfld):
    """ Main Class that provides methods used by the Vxlan Registration Daemon.
    """
    __IP_ADDR_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

    __BRPORT_MAC_ADDR = '00:00:00:00:00:00'

    __VXLAN_REGEX = re.compile(
        r'^\d+: (?P<dev_name>\S+):'
        r'(?=.*state\s+(?P<state>\S+))'
        r'(?=.*vxlan\s+id\s+(?P<vni>\d+))'
        r'(?=.*dstport\s+(?P<dstport>\d+))?'
        r'(?=.*local\s+(?P<local_addr>{0}))?'
        r'(?=.*(?:svcnode|remote)\s+(?P<sn_addr>{0}))?'.format(__IP_ADDR_REGEX)
    )

    __BRPORT_REGEX = re.compile(
        r'^{0}'
        r'(?=.*dst\s+(?P<dst_addr>{1}))'
        r'(?=.*dev\s+(?P<dev_name>\S+))'.format(__BRPORT_MAC_ADDR,
                                                __IP_ADDR_REGEX)
    )

    def __init__(self, conf):
        super(_Vxrd, self).__init__(conf)
        self.__vni_config = {}  # vni_config[vni] = DeviceConfig
        self.__peerdb = {}      # peerdb[vni] = {ip, ...}
        self.__sock = None
        if self._conf.head_rep:
            # Cumulus Linux: When operating in HER mode, the RD should limit
            # the pool size to 1 inorder to avoid the situation where multiple
            # threads update the kernel state in parallel.
            self.__herpool = eventlet.GreenPool(size=1)
            # Used to keep track of when the last response was received from
            # the SND.
            self.__last_response = None
            # To ensure deletes are sent before adds
            self.__removed = self.__update_event = None

    def _run(self):
        """ Periodically sends the registration method to the svcnode address.
        Usually at regular time intervals but may be accelerated if
        membership has changed.
        """
        # Open a socket for sending the refresh msgs
        try:
            self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.__sock.bind((self._conf.src_ip, self._conf.vxfld_port))
        except socket.error as ex:
            raise RuntimeError('opening transmit socket : %s' % ex)
        if self._conf.head_rep:
            self._pool.spawn_n(self._serve, self.__sock,
                               self.__handle_vxfld_msg,
                               pool=self.__herpool)
        next_refresh = 0
        next_config_check = 0
        while True:
            now = int(time.time())
            if now >= next_config_check:
                next_config_check = now + self._conf.config_check_rate
                current = self.__get_vxlan_config()
                if current is not None and self.__vni_config != current:
                    old, self.__vni_config = self.__vni_config, current
                    added = {vni: vni_config
                             for vni, vni_config in current.iteritems()
                             if vni not in old}
                    # Updated VNIs are those for which the VTEP's source
                    # address has changed. This check is needed because the
                    # VNI can move to a new source address when CLAGd detects
                    # a failure and replaces the anycast source address with a
                    # unicast one.
                    updated = {
                        vni: vni_config for vni, vni_config in old.iteritems()
                        if vni in current and (
                            current[vni].localip != vni_config.localip or
                            current[vni].svcnodeip != vni_config.svcnodeip
                        )
                    }
                    if self.__remove_vnis(old, current, updated=updated):
                        # Send the updated configuration to the SND once
                        # the delete message has been acknowledged.
                        if added or updated:
                            # VXLAN config has changed.  Send refresh
                            # immediately. Merge updated and added VNIs and
                            # send an update to the SND. Schedule another
                            # refresh in 1 sec just in case the UDP msg is
                            # lost.
                            self.__send_refresh(self.__vni_config,
                                                self._conf.holdtime)
                            next_refresh = now + 1
                    else:
                        # Delete message has not been acknowledged. Revert
                        # back to the old config.
                        self.__vni_config = old
                    if self._conf.head_rep:
                        # HER: Keep the peerdb and bridge fdb entries in sync.
                        hrep_updated = {}
                        for vni, vni_config in current.iteritems():
                            peerips = self.__peerdb.get(vni, set())
                            myaddr = {vni_config.localip}
                            if vni in old:
                                myaddr.add(old[vni].localip)
                            if vni_config.hrep_addrs ^ peerips - myaddr:
                                hrep_updated[vni] = peerips
                        if hrep_updated:
                            self.__herpool.spawn(self.__update_peerdb,
                                                 hrep_updated, current).wait()
            if (self._conf.head_rep and
                    self.__last_response is not None and
                    (now - self.__last_response) > self._conf.holdtime):
                # HER: Flush the peerdb and HREP MAC entries if the RD
                # hasn't heard from the SND in more than holdtime seconds.
                self._logger.warning('Lost contact with SND. Cleaning up...')
                self.__last_response = None
                self.__remove_vnis(self.__vni_config, {})
            if now >= next_refresh:
                self.__send_refresh(self.__vni_config, self._conf.holdtime)
                next_refresh = (
                    now + self._conf.holdtime / self._conf.refresh_rate
                )
            eventlet.sleep(max(0, min(next_refresh - now,
                                      next_config_check - now)))

    def __get_vxlan_config(self, vnis=None):
        """ Parses the output of 'bridge fdb show' and 'ip link show' to map
         a VNI to a DeviceConfig object.
        :param vnis: used to filter the output of this method
        :returns: a dictionary mapping VNIs to DeviceConfig objects if
                  successful, otherwise None.
        """
        vni_config = {}
        dev_map = collections.defaultdict(set)
        if self._conf.head_rep:
            # Map the device to bridge fdb entries.
            bridgecmd = (
                '/sbin/bridge fdb show | /bin/grep %s' % self.__BRPORT_MAC_ADDR
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
                bridge = subprocess.Popen(bridgecmd,
                                          stdout=subprocess.PIPE,
                                          shell=True)
            except Exception as ex:  # pylint: disable=broad-except
                self._logger.warning('Command failed. out:%s', ex)
                return None
            for line in iter(bridge.stdout.readline, b''):
                pat_match = self.__BRPORT_REGEX.match(line.rstrip())
                if pat_match is not None:
                    pat_dict = pat_match.groupdict()
                    dev_map[pat_dict['dev_name']].add(pat_dict['dst_addr'])
            bridge.wait()
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
                if (
#                        match_dict['dstport'] is None or
                        match_dict['local_addr'] is None or
                        (not self._conf.head_rep and
                         match_dict['sn_addr'] is None)
                ):
                    self._logger.warning('Invalid configuration %s detected '
                                         'for device. Skipping', match_dict)
                    continue
                if match_dict['state'] in ['UP', 'UNKNOWN']:
                    svcnode_ip = self._conf.svcnode_ip
                    # If the svcnode_ip is not set in the configuration,
                    # then use the VTEP's svcnode IP in the kernel.
                    if (svcnode_ip ==
                            config.Config.CommonConfig.svcnode_ip.default and
                            match_dict['sn_addr'] is not None):
                        svcnode_ip = match_dict['sn_addr']
                    # got vni, local and sn.  Add to dict
                    if vnis is None or vni in vnis:
                        vni_config[vni] = _DeviceConfig(
                            dev_name=match_dict['dev_name'],
                            localip=match_dict['local_addr'],
                            svcnodeip=svcnode_ip,
                            hrep_addrs=dev_map[match_dict['dev_name']]
                        )
        if iplinkshow.wait() == 0:
            return vni_config
        else:
            self._logger.error('%s returned non-zero exit code', cmd)
            return None

    def _process(self, msg):
        """ Returns result object and Exception.
        """
        # pylint: disable=too-many-return-statements
        try:
            if msg['vxlans']:
                if msg['hrep'] and not self._conf.head_rep:
                    return None, None
                return self.__vni_config, None
            elif msg['peers']:
                if self._conf.head_rep:
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
            else:
                return None, RuntimeError('Unknown request')
        except Exception:  # pylint: disable=broad-except
            return None, RuntimeError('Bad message')

    def __send_refresh(self, vni_data, hold):
        """ Sends a refresh message to the SND
        :param vni_data: dictionary mapping VNIs to DeviceConfig objects
        :param hold: holdtimer
        """
        # pylint: disable=missing-docstring
        # Build the right datastructure for the message
        # need msg_data as {svcnode: {vni: [local]}}
        def send_vxfld_pkt(pkt_in, svcnode_in):
            self._logger.debug('Sending to %s: %s. Holdtime: %s', svcnode_in,
                               pkt_in.data.vni_vteps.items(), hold)
            try:
                self.__sock.sendto(str(pkt_in),
                                   (svcnode_in, self._conf.vxfld_port))
            except Exception as ex:  # pylint: disable=broad-except
                self._logger.error('Error sending refresh packet: %s',
                                   type(ex))
        for svcnode, grouper in itertools.groupby(
                vni_data, lambda k: vni_data.get(k).svcnodeip):
            vxfld_pkt = refresh_pkt = None
            for vni in grouper:
                addrs = [vni_data.get(vni).localip]
                # Limit the refresh message to max_packet_size.
                if (vxfld_pkt is None or
                        VXFLD.BASE_PKT_SIZE + len(vxfld_pkt) +
                        len(VXFLD.Refresh.vtep_to_str(vni, addrs)) >=
                        self._conf.max_packet_size):
                    if vxfld_pkt is not None:
                        send_vxfld_pkt(vxfld_pkt, svcnode)
                    vxfld_pkt = VXFLD.Packet()
                    vxfld_pkt.version = VXFLD.VERSION
                    refresh_pkt = VXFLD.Refresh(version=VXFLD.VERSION,
                                                holdtime=hold,
                                                originator=True)
                    vxfld_pkt.type = refresh_pkt.type
                    vxfld_pkt.data = refresh_pkt
                    if self._conf.head_rep:
                        refresh_pkt.response_type = (
                            VXFLD.ResponseType.REQUESTED
                        )
                refresh_pkt.add_vni_vteps({vni: addrs})
            if refresh_pkt is not None and refresh_pkt.vni_vteps:
                send_vxfld_pkt(vxfld_pkt, svcnode)

    def __remove_vnis(self, old, current, updated=None):
        """ This function handles the cleanup of VNIs that have either been
        updated or removed from the config by sending a refresh message with
        holdtime of 0 so that vxsnd can quickly age these out. It also removes
        the peer list for VNIs that have been removed from the config.
        :param old: Old configuration of the following format
                {vni: DeviceConfig}
        :param current: New configuration of the following format
                {vni: DeviceConfig}
        :param updated: dictionary of the following format
                {vni: DeviceConfig}
        :returns True if message was either not sent or sent and acknowledged,
                 False if it wasn't acknowledged.
        """
        status = True
        # Removed VNIs are those that have been unconfigured fromt the device.
        removed = {vni: vni_config
                   for vni, vni_config in old.iteritems()
                   if vni not in current}
        if removed or updated:
            # Merge updated and removed VNIs and send an update to the SND.
            refresh = removed.copy()
            refresh.update(updated or {})
            if self._conf.head_rep:
                self.__update_event = Event()
                self.__removed = refresh
                no_of_attempts = 3
                for _ in range(no_of_attempts):
                    self.__send_refresh(refresh, 0)
                    eventlet.sleep(1)
                    if self.__update_event.ready():
                        break
                else:
                    self._logger.warning('Did not receive an acknowledgement '
                                         'from the SND after %d attempts',
                                         no_of_attempts)
                    status = False
                self.__removed = self.__update_event = None
            else:
                self.__send_refresh(refresh, 0)
        if self._conf.head_rep and removed:
            # HER: Remove VNIs that are no longer configured on the device.
            # Using the herpool guarantees that updates to the bridge fdb are
            # sequential.
            self.__herpool.spawn(self.__update_peerdb,
                                 {vni: set() for vni in removed
                                  if self.__peerdb.get(vni, set())},
                                 old).wait()
        return status

    def __handle_vxfld_msg(self, buf, addr):
        """ HER: Handles the VXFLD message.
        :param buf: socket buffer
        :param addr: source address
        This is specific to Cumulus Linux.
        """
        srcip, _ = addr
        self.__last_response = int(time.time())
        try:
            vxfld_pkt = VXFLD.Packet(buf)
        except Exception as ex:  # pylint: disable=broad-except
            self._logger.error('Unknown VXFLD packet received from %s: %s',
                               srcip, ex.message)
            return
        refresh_pkt = vxfld_pkt.data
        if vxfld_pkt.type > VXFLD.MsgType.REFRESH:
            self._logger.warning('Unexpected vxfld pkt of type %d',
                                 vxfld_pkt.type)
            return
        self._logger.debug('Refresh msg from %s: %s', srcip,
                           refresh_pkt.vni_vteps)
        if self.__removed is not None and self.__update_event is not None:
            if (set(refresh_pkt.vni_vteps) ^ set(self.__removed) or
                    any(self.__removed[vni].localip in iplist
                        for vni, iplist in refresh_pkt.vni_vteps.iteritems())):
                self._logger.debug('Refresh msg ignored because VNI deletion '
                                   'is in progress')
                return
            else:
                self._logger.debug('Received ack for deleted vnis %s',
                                   set(self.__removed))
                self.__update_event.send(True)
        # Compute the list of updated VNIs
        updated_vnis = {
            vni: set(iplist)
            for vni, iplist in refresh_pkt.vni_vteps.iteritems()
            if set(iplist) != self.__peerdb.get(vni, set())
        }
        if updated_vnis:
            self.__update_peerdb(updated_vnis, self.__vni_config)

    def __update_peerdb(self, updated_vnis, vni_config):
        """ HER: Update the RD's peerdb.
        :param updated_vnis: a dictionary mapping VNIs to a set of peer
                             IP addresses
        :param vni_config: a dictionary mapping VNIs to DeviceConfig objects
                           {vni: DeviceConfig}
        :returns: None if successful, otherwise raises an Exception.
        This is specific to Cumulus Linux.
        """
        def update_bridgefdb(filepath):
            """ Updates the bridge fdb by calling the bridge command with the
             temporary batch file as input.
            :param filepath: location of the temporary batch file
            :return: None.
            We ignore the return value because the periodic config scan will
            synchronize the kernel state with the peerdb.
            """
            cmd = '/sbin/bridge -force -batch %s' % filepath
            try:
                subprocess.check_output(cmd.split(),
                                        stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as ex:
                self._logger.info('Failed to update bridge fdb. out: %s',
                                  ex.output)
        max_cmds_per_batch = 2000
        with tempfile.NamedTemporaryFile('w', prefix='vxrd_tmp') as tmpf:
            no_of_commands = 0
            for vni, ipset in updated_vnis.iteritems():
                if vni not in vni_config:
                    self._logger.debug('Unexpected VNI %d', vni)
                    continue
                dev_name = vni_config[vni].dev_name
                my_addr = vni_config[vni].localip
                cur_addrs = vni_config[vni].hrep_addrs
                self._logger.debug('Updating peer list for VTEP %s. new: %s. '
                                   'peerdb: %s, hrep: %s, myaddr: %s',
                                   dev_name, ipset,
                                   self.__peerdb.get(vni, set()),
                                   cur_addrs, my_addr)
                if ipset:
                    self.__peerdb[vni] = ipset
                else:
                    self.__peerdb.pop(vni, None)
                for operation, peerips in \
                        (('del', cur_addrs - (ipset - {my_addr})),
                         ('append', ipset - cur_addrs - {my_addr})):
                    for peerip in peerips:
                        tmpf.write('fdb %s %s dev %s dst %s\n' % (
                            operation, self.__BRPORT_MAC_ADDR, dev_name,
                            peerip))
                        if no_of_commands == max_cmds_per_batch - 1:
                            tmpf.flush()
                            update_bridgefdb(tmpf.name)
                            no_of_commands = 0
                            tmpf.truncate(0)
                            tmpf.seek(0)
                        else:
                            no_of_commands += 1
            if no_of_commands:
                tmpf.flush()
                update_bridgefdb(tmpf.name)


def main():
    """ Main method
    """
    prsr = utils.common_parser(_NODE_NAME, NODE_TYPE)
    args = prsr.parse_args()
    conf = utils.load_configuration(args)
    vxrd_inst = _Vxrd(conf)
    return vxrd_inst.run()
