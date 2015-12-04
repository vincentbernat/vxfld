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
""" Utility functions.
"""
import argparse
import fcntl
import gzip
import json
import logging
import logging.handlers
import os
import sys

from vxfld.common import config
from vxfld.common.enums import (
    DefaultConfFile,
    LogDestination,
    NodeType
)


class _CompressedRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """ Extended version of RotatingFileHandler that compresses logs on
    rollover.
    Inspired by http://stackoverflow.com/questions/8467978/
    python-want-logging-with-log-rotation-and-compression
    """
    def doRollover(self):
        """ do a rollover; in this case, a date/time stamp is appended to the
        filename when the rollover happens.  However, you want the file to be
        named for the start of the interval, not the current time.  If there
        is a backup count, then we have to get a list of matching filenames,
        sort them and remove the one with the oldest suffix.
        """
        if self.stream:
            self.stream.close()
            self.stream = None
        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = '%s.%d.gz' % (self.baseFilename, i)
                dfn = '%s.%d.gz' % (self.baseFilename, i + 1)
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)
            dfn = self.baseFilename + '.1.gz'
            if os.path.exists(dfn):
                os.remove(dfn)
            if os.path.exists(self.baseFilename):
                with open(self.baseFilename, 'rb') as f_in:
                    with gzip.open(dfn, 'wb') as f_out:
                        f_out.writelines(f_in)
                os.remove(self.baseFilename)
        if not getattr(self, 'delay', None):
            self.stream = self._open()


def common_parser(node_type):
    """ Argparser for common command-line arguments.
    :param node_type (NodeType): can be vxrd or vxsnd
    :return: an argument parser object for parsing command line strings into
    Python objects
    """
    prsr = argparse.ArgumentParser()
    if node_type == NodeType.VXRD:
        default_conf_file = DefaultConfFile.VXRD
    else:
        default_conf_file = DefaultConfFile.VXSND
    prsr.add_argument('-c', '--config-file',
                      default=default_conf_file,
                      help='The config file to read in at startup')
    prsr.add_argument('-d', '--daemon',
                      action='store_true',
                      help='Run as a daemon program')
    prsr.add_argument('-p', '--pidfile',
                      help='File to write the process ID')
    prsr.add_argument('-u', '--udsfile',
                      help='Unix domain socket for mgmt interface')
    prsr.add_argument('-D', '--debug',
                      action='store_true',
                      help='Turn on extra debug mode')
    return prsr


def get_config_params(node_type, reloadable=False):
    """ Outputs a space separated list of configuration params supported by
    the daemon.
    :param node_type (NodeType): can be vxrd or vxsnd
    :param reloadable: if True, then only reloadable parameters are displayed
    :return: None
    """
    conf = config.Config(node_type, '')
    print ' '.join({param for param in conf.get_params()
                    if not reloadable or conf.is_reloadable(param)})


def get_logger(node_type, logdest, filehandler_args=None):
    """ Return a logger for the specified node name, creating it if necessary.
    :param node_type (NodeType): vxfld node type
    :param logdest (LogDestination): log file destination
    :param filehandler_args: dict that provides the 'filename' (mandatory),
    'maxBytes' and 'backupCount' required by the rotating file handler
    :return: logger object.
    """
    logger = logging.getLogger(node_type)
    lgr_fmt = '%%(asctime)s %s %%(levelname)s: %%(message)s' % node_type
    syslog_fmt = '%s: %%(levelname)s: %%(message)s' % node_type
    date_fmt = '%H:%M:%S'
    if logdest == LogDestination.SYSLOG:
        log_handler = logging.handlers.SysLogHandler(address='/dev/log')
        log_formatter = logging.Formatter(fmt=syslog_fmt)
    elif logdest == LogDestination.STDOUT:
        log_handler = logging.StreamHandler(stream=sys.stdout)
        log_formatter = logging.Formatter(lgr_fmt, date_fmt)
    elif logdest == LogDestination.LOGFILE:
        if filehandler_args is None or 'filename' not in filehandler_args:
            raise RuntimeError('Filename not provided in '
                               'filehandler_args %s' % filehandler_args)
        log_handler = _CompressedRotatingFileHandler(
            filename=filehandler_args['filename'],
            maxBytes=filehandler_args.get('maxBytes', 0),
            backupCount=filehandler_args.get('backupCount', 0))
        log_formatter = logging.Formatter(lgr_fmt, date_fmt)
    else:
        raise RuntimeError('Invalid logdest %s' % logdest)
    log_handler.setFormatter(log_formatter)
    logger.addHandler(log_handler)
    return logger


def load_configuration(node_type, args):
    """ Load configuration.
    :param node_type (NodeType): vxfld node type
    :param args: parsed command-line arguments
    :return: a configuration (Config) object
    """
    conf = config.Config(node_type, args.config_file)
    for param, val in vars(args).iteritems():
        if val is not None:
            setattr(conf, param, val)
    return conf


class Pidfile(object):
    """ Checks if another instance of the program is running.
    Explanation from http://stackoverflow.com/questions/220525/
    ensure-a-single-instance-of-an-application-in-linux

    The Right Thing is advisory locking using flock(LOCK_EX); in Python,
    this is found in the fcntl module.

    Unlike pidfiles, these locks are always automatically released when
    your process dies for any reason, have no race conditions exist
    relating to file deletion (as the file doesn't need to be deleted to
    release the lock), and there's no chance of a different process
    inheriting the PID and thus appearing to validate a stale lock.

    If you want unclean shutdown detection, you can write a marker
    (such as your PID, for traditionalists) into the file after
    grabbing the lock, and then truncate the file to 0-byte status
    before a clean shutdown (while the lock is being held); thus, if the
    lock is not held and the file is non-empty, an unclean shutdown is
    indicated.
    """
    # pylint: disable=missing-docstring
    def __init__(self, pidfile, procname, uuid=None):
        try:
            self.__pidfd = open(pidfile, 'ab+')
        except IOError as err:
            err.extra_info = 'Failed to open pidfile: %s' % pidfile
            raise
        self.__pidfile = pidfile
        self.__procname = procname
        self.__uuid = uuid

    def __str__(self):
        return self.__pidfile

    def is_running(self):
        pid = self.read()
        if pid is None:
            return False
        cmdline = '/proc/%s/cmdline' % pid
        try:
            with open(cmdline, 'r') as pidfd:
                exec_out = pidfd.readline()
            return self.__procname in exec_out and (not self.__uuid or
                                                    self.__uuid in exec_out)
        except IOError:
            return False

    def lock(self):
        try:
            fcntl.flock(self.__pidfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            raise RuntimeError('Another instance of this program is already '
                               'running.')

    def read(self):
        try:
            self.__pidfd.seek(0)
            return int(self.__pidfd.readline().strip())
        except Exception:  # pylint: disable=broad-except
            return

    def unlock(self):
        try:
            fcntl.flock(self.__pidfd, fcntl.LOCK_UN)
        except IOError:
            raise RuntimeError('Unable to unlock pid file.')

    def write(self, pid):
        self.__pidfd.truncate(0)
        self.__pidfd.write('%d\n' % pid)
        self.__pidfd.flush()


class SetEncoder(json.JSONEncoder):
    """ Custom encoder that returns a list when it encounters a set.
    """
    def __init__(self, *args, **kwargs):
        kwargs.pop('default', None)
        super(SetEncoder, self).__init__(*args, **kwargs)

    def default(self, obj):  # pylint: disable=method-hidden
        """ Returns a list on encountering a set object or a set as an
        attribute of the object.
        """
        if isinstance(obj, set):
            return list(obj)
        elif hasattr(obj, '__dict__'):
            return {
                attr: (value if not isinstance(value, set)
                       else self.default(value))
                for attr, value in vars(obj).iteritems()
            }
        return super(SetEncoder, self).default(obj)
