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
""" Common constants.
"""
# pylint: disable=too-few-public-methods


class ConfigSection(object):
    """ Section name in configuration file.
    """
    COMMON = 'common'
    VXRD = 'vxrd'
    VXSND = 'vxsnd'

    def __init__(self):
        raise NotImplementedError


class DefaultConfFile(object):
    """  Default daemon configuration files
    """
    VXRD = '/etc/vxrd.conf'
    VXSND = '/etc/vxsnd.conf'

    def __init__(self):
        raise NotImplementedError


class DefaultPidFile(object):
    """  Default daemon pid files
    """
    VXRD = '/var/run/vxrd.pid'
    VXSND = '/var/run/vxsnd.pid'

    def __init__(self):
        raise NotImplementedError


class DefaultUdsFile(object):
    """  Default daemon UDS files
    """
    VXRD = '/var/run/vxrd.sock'
    VXSND = '/var/run/vxsnd.sock'

    def __init__(self):
        raise NotImplementedError


class LogDestination(object):
    """  Destination for log messages.
    """
    SYSLOG = 'syslog'
    STDOUT = 'stdout'
    LOGFILE = 'logfile'

    def __init__(self):
        raise NotImplementedError


class NodeType(object):
    """ VXFLD node type.
    """
    VXRD = 'vxrd'
    VXSND = 'vxsnd'
    VALUES = [VXRD, VXSND]

    def __init__(self):
        raise NotImplementedError


class OperState(object):
    """ Oper state (netdevice->operstate).
    Defined in /usr/include/linux/if.h
    """
    # pylint: disable=too-few-public-methods
    IF_OPER_UNKNOWN = 0
    IF_OPER_NOTPRESENT = 1
    IF_OPER_DOWN = 2
    IF_OPER_LOWERLAYERDOWN = 3
    IF_OPER_TESTING = 4
    IF_OPER_DORMANT = 5
    IF_OPER_UP = 6

    OPERSTATE_STR = {
        IF_OPER_UNKNOWN: 'UNKNOWN',
        IF_OPER_NOTPRESENT: 'NOTPRESENT',
        IF_OPER_DOWN: 'DOWN',
        IF_OPER_LOWERLAYERDOWN: 'LOWERLAYERDOWN',
        IF_OPER_TESTING: 'TESTING',
        IF_OPER_DORMANT: 'DORMANT',
        IF_OPER_UP: 'UP'
    }

    def __init__(self):
        raise NotImplementedError
