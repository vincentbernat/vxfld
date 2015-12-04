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
""" Stuff that is common to both vxfld daemons.
"""
from abc import ABCMeta, abstractmethod
import atexit
import logging
import logging.handlers
import os
import signal
import socket
import sys

from daemon import daemon
import eventlet
import greenlet

from vxfld.common import mgmt, utils, eventlet_backdoor
from vxfld.common.enums import LogDestination


class Vxfld(object):
    """ Abstract base class that provides methods common to both Vxsnd and
    Vxrd.
    """
    __metaclass__ = ABCMeta

    def __init__(self, conf):
        self._conf = conf
        # Set up signal handlers before daemonizing
        self.__setup_signal_handlers()
        self.__daemon_context = daemon.DaemonContext(
            working_directory='/var/run'
        )
        if self._conf.daemon:
            self.__daemon_context.open()
        # Patch system modules to be greenthread-friendly. Must be after
        # daemonizing.
        eventlet.monkey_patch()
        self._pool = eventlet.GreenPool(size=self._conf.concurrency)
        self.__run_gt = None
        # Set up logging. Must be after daemonizing.
        if self._conf.debug:
            lvl = logging.DEBUG
            self.__spawn_backdoor_server()
        else:
            lvl = getattr(logging, self._conf.loglevel)
        if self._conf.logdest in {LogDestination.SYSLOG,
                                  LogDestination.STDOUT}:
            self._logger = utils.get_logger(self._conf.node_type,
                                            self._conf.logdest)
        else:
            self._logger = utils.get_logger(
                self._conf.node_type,
                LogDestination.LOGFILE,
                filehandler_args={'filename': self._conf.logdest,
                                  'maxBytes': self._conf.logfilesize,
                                  'backupCount': self._conf.logbackupcount}
            )
        self._logger.setLevel(lvl)
        self._mgmtserver = mgmt.MgmtServer(self._conf.udsfile,
                                           self._process,
                                           self._logger)
        self.__pidfd = utils.Pidfile(self._conf.pidfile,
                                     self._conf.node_type,
                                     uuid=self._conf.node_id)

    @abstractmethod
    def _process(self, msg):
        """ Returns a response object and an Exception object. The
        latter is None if no exception.

        Over-ride this method in the derived class
        """
        raise NotImplementedError

    @abstractmethod
    def _run(self):
        """ Run method to be implemented by the Derived class.
        """
        raise NotImplementedError

    def _serve(self, sock, handle, pool=None, bufsize=None, err_cbs=None):
        """ Runs a server on the supplied socket.  Calls the function *handle*
        in a separate greenthread for every incoming client connection.
        *handle* takes two arguments: the client socket object, and the client
        address.
        """
        # pylint: disable=too-many-arguments
        err_cbs = err_cbs or {}
        while True:
            try:
                bufsize = bufsize or self._conf.max_packet_size
                buf, addr = sock.recvfrom(bufsize)
                pool = pool or self._pool
                green_thread = pool.spawn(handle, buf, addr)
                green_thread.link(self._stop_checker)
            except socket.error as (err, _):
                if err in err_cbs:
                    err_cbs[err]()
                    return
                else:
                    raise
            except eventlet.StopServe:
                return

    def _stop_checker(self, green_thread):
        """ Propagates exceptions raised by a green thread to the run
        green thread.
        """
        try:
            green_thread.wait()
        except greenlet.GreenletExit:  # pylint: disable=no-member
            pass
        except Exception:  # pylint: disable=broad-except
            eventlet.kill(self.__run_gt, *sys.exc_info())

    def __delpid(self):
        """ Removes the pidfile when the process exits gracefully.
        """
        try:
            os.remove(self._conf.pidfile)
        except OSError:
            self._logger.exception('Unable to remove pid file on exit')

    def __setup_signal_handlers(self):
        """ Set up signal handlers.
        """
        signal.signal(signal.SIGINT, self.__term_handler)
        signal.signal(signal.SIGTERM, self.__term_handler)
        signal.signal(signal.SIGHUP, self.__term_handler)

    def __spawn_backdoor_server(self):
        """ Sets up an interactive console on a socket with a single connected
        client.
        """
        eventlet_backdoor.initialize_if_enabled(
            self._conf.eventlet_backdoor_port)

    def __term_handler(self, signum, _):
        """ Signal handler that terminates the process.
        """
        msg = 'Caught signal %d' % signum
        self._logger.debug(msg)
        eventlet.kill(self.__run_gt, SystemExit(msg))

    def get_logger(self):
        """ Returns the logger object for the instance.
        """
        return self._logger

    def run(self):
        """ Once upon a time...
        """
        try:
            # Make sure that I am not already running
            pid = os.getpid()
            self.__pidfd.lock()
            self.__pidfd.write(pid)
            atexit.register(self.__delpid)
            self._logger.info('Starting (pid %d) ...', pid)
            atexit.register(self._logger.info,
                            'Terminating (pid %d)' % pid)
            self.__run_gt = self._pool.spawn(self._run)
            self._pool.spawn(self._mgmtserver.run).link(self._stop_checker)
            self.__run_gt.wait()
        except SystemExit:
            raise
        except RuntimeError as ex:
            self._logger.error('Error: %s', ex)
            raise
        except Exception:  # pylint: disable=broad-except
            self._logger.exception('Error: ')
            raise
        finally:
            self.__daemon_context.close()
