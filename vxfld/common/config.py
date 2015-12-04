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
""" Configuration file parser.
"""
# pylint: disable=too-few-public-methods
from ConfigParser import RawConfigParser, NoSectionError
import logging
import socket
import uuid

from vxfld.common.enums import (
    ConfigSection,
    DefaultPidFile,
    DefaultUdsFile,
    NodeType
)


class Field(object):
    """ Field object.
    """
    def __init__(self, default, reloadable=False, nullable=False):
        self.name = None
        self.section = None
        self.default = default
        self.reloadable = reloadable
        self.nullable = nullable

    def __call__(self, value):
        """ Validates the value passed to this method.

        Derived classes can override this function to provide custom
        validation.
        """
        return value

    def tostr(self, value):
        """ Returns a display friendly value.

        Derived classes can override this method to provide custom
        behavior.
        """
        # pylint: disable=no-self-use
        return value


class AddressField(Field):
    """ Address object.
    """
    def __call__(self, value):
        """ Returns the result of gethostbyname on a string.

        Verifies correctness of a dotted decimal specification.
        """
        if value is None:
            return value
        try:
            return socket.gethostbyname(value.strip('\'\"'))
        except Exception:  # pylint: disable=broad-except
            raise RuntimeError('Invalid address %s' % value)


class BooleanField(Field):
    """ Boolean object.
    """
    def __call__(self, value):
        """ Check if a value can be converted to a boolean.
        """
        if value is None:
            return None
        try:
            return str(value).lower() in ('1', 'on', 'yes', 'true')
        except Exception:  # pylint: disable=broad-except
            raise RuntimeError('Invalid boolean value %s' % value)


class IntegerField(Field):
    """ Integer object.
    """
    def __call__(self, value):
        """ Check if a value can be converted to an integer.
        """
        if value is None:
            return None
        try:
            return int(value)
        except Exception:  # pylint: disable=broad-except
            raise RuntimeError('Invalid integer value %s' % value)


class LogLevelField(Field):
    """ LogLevel object.
    """
    def __call__(self, value):
        """ Get the the log level.
        If successful, returns the numeric value corresponding to one of the
        defined levels passed to the method.
        """
        lvl = logging.getLevelName(value.upper())
        if isinstance(lvl, basestring):
            raise RuntimeError('Invalid log level %s' % value)
        return value


class ServerField(Field):
    """ Server object.
    """
    def __call__(self, value):
        """ Split the string and resolve to set of addresses.
        """
        result = set()
        if value is None:
            return result
        addr_field = AddressField(None)
        for server in value.split():
            try:
                host, port = server.split(':')
                port = int(port)
            except ValueError:
                host = server
                port = None
            result.add((addr_field(host), port))
        return result

    def tostr(self, value):
        if not value and self.nullable:
            return None
        return ', '.join(ip_addr for ip_addr, port in value)


class _ConfigMeta(type):
    """ Meta class that sets the section and name on an instance of
    ConfigField.
    """
    def __new__(mcs, name, bases, class_dict):
        for key, value in class_dict.items():
            if isinstance(value, Field):
                value.name = key
                value.section = class_dict['section']
        return type.__new__(mcs, name, bases, class_dict)


class Config(object):
    """ Generic Config class.
    """

    class CommonConfig(object):
        """ Common configuration parameters.
        """
        # pylint: disable=too-few-public-methods
        __metaclass__ = _ConfigMeta

        section = ConfigSection.COMMON
        concurrency = IntegerField(default=1000)
        debug = BooleanField(default=False, reloadable=True)
        eventlet_backdoor_port = IntegerField(default=9000)
        holdtime = IntegerField(default=90, reloadable=True)
        # no of log files to store on the disk
        logbackupcount = IntegerField(default=14)
        logdest = Field(default='syslog')
        # log file size in bytes
        logfilesize = IntegerField(default=500 * 1024)
        loglevel = LogLevelField(default=logging.getLevelName(logging.INFO),
                                 reloadable=True)
        max_packet_size = IntegerField(default=1500)
        node_id = IntegerField(default=uuid.getnode())
        pidfile = Field(default=None, nullable=True)
        src_ip = AddressField(default='0.0.0.0')
        svcnode_ip = AddressField(default='0.0.0.0')
        udsfile = Field(default=None, nullable=True)
        vxfld_port = IntegerField(default=10001)

    class VxrdConfig(object):
        """ Vxrd specific configuration parameters.
        """
        # pylint: disable=too-few-public-methods
        __metaclass__ = _ConfigMeta

        section = ConfigSection.VXRD
        config_check_rate = IntegerField(default=60, reloadable=True)
        head_rep = BooleanField(default=True, reloadable=True)
        refresh_rate = IntegerField(default=3, reloadable=True)

    class VxsndConfig(object):
        """ Vxsnd specific configuration parameters.
        """
        # pylint: disable=too-few-public-methods
        __metaclass__ = _ConfigMeta

        area = IntegerField(default=None, nullable=True)
        age_check = IntegerField(default=90, reloadable=True)
        enable_flooding = BooleanField(default=True, reloadable=True)
        enable_vxlan_listen = BooleanField(default=True)
        install_svcnode_ip = BooleanField(default=False)
        proxy_id = AddressField(default=None, reloadable=True, nullable=True)
        proxy_local_only = BooleanField(default=True, reloadable=True)
        receive_queue = IntegerField(default=131072)
        refresh_proxy_servers = BooleanField(default=False, reloadable=True)
        section = ConfigSection.VXSND
        svcnode_peers = ServerField(default=None, reloadable=True,
                                    nullable=True)
        sync_from_proxy = BooleanField(default=False)
        sync_targets = IntegerField(default=1)
        vxlan_port = IntegerField(default=4789)
        vxlan_dest_port = IntegerField(default=None, nullable=True)
        vxlan_listen_port = IntegerField(default=None, nullable=True)
        vxfld_proxy_servers = ServerField(default=None, reloadable=True,
                                          nullable=True)

    def __init__(self, node_type, config_file):
        self.__params = self.__get_fields(self.CommonConfig)
        self.node_type = node_type
        if node_type == NodeType.VXRD:
            self.__params.update(self.__get_fields(self.VxrdConfig))
            pidfile = DefaultPidFile.VXRD
            udsfile = DefaultUdsFile.VXRD
        elif node_type == NodeType.VXSND:
            self.__params.update(self.__get_fields(self.VxsndConfig))
            pidfile = DefaultPidFile.VXSND
            udsfile = DefaultUdsFile.VXSND
        else:
            raise RuntimeError('Invalid node type %s. Acceptable values are '
                               '%s' % (node_type, ', '.join(NodeType.VALUES)))
        default_dict = {field.name: field.default for field in self.__params}
        config_parser = RawConfigParser(defaults=default_dict,
                                        allow_no_value=True)
        config_parser.read([config_file, config_file + '.override'])
        for field in self.__params:
            try:
                value = config_parser.get(field.section, field.name)
            except NoSectionError:
                value = field.default
            setattr(self, field.name, field(value))
        self.pidfile = self.pidfile or pidfile
        self.udsfile = self.udsfile or udsfile

    @staticmethod
    def __get_fields(class_):
        """ Returns a set of ConfigField objects for a class.
        """
        return {
            field for field in class_.__dict__.itervalues()
            if isinstance(field, Field)
        }

    def get_params(self):
        """ Returns a dict of (param_name, param_value) for all sections in
        the configuration.
        """
        return {
            field.name: field.tostr(getattr(self, field.name))
            for field in self.__params
        }

    def is_nullable(self, name):
        """ Return True if a parameter is nullable, False otherwise.
        """
        field = next(field for field in self.__params if field.name == name)
        return field.nullable

    def is_reloadable(self, name):
        """ Return True if a parameter is reloadable, False otherwise.
        """
        field = next(field for field in self.__params if field.name == name)
        return field.reloadable

    def set_param(self, name, val):
        """ Sets an attribute to the provided value.
        """
        field = next(field for field in self.__params if field.name == name)
        setattr(self, name, field(val))
