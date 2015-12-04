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
""" Client and Server for Management.
"""
import os
import pickle
import socket
import struct

import eventlet


class MgmtServer(object):
    """ The daemon runs the server object in a thread and
    responds to these requests.  The response is two objects: the valid
    response if no error and an exception object if there is an error.
    One of the two should be None.
    See the test code for typical usage.
    """
    # pylint: disable=too-few-public-methods
    __BUF_SIZE = 4 * 1024

    # pylint: disable=no-member
    def __init__(self, uds_file, process_cb, logger, concurrency=10):
        self.__uds_file = uds_file
        self.__socket = socket.socket(socket.AF_UNIX,
                                      socket.SOCK_STREAM)
        self.__concurrency = concurrency
        self.__logger = logger
        self.__process = process_cb

    def __handle_msg(self, conn, _):
        """ Main run method.
        """
        try:
            msg = pickle.loads(conn.recv(self.__BUF_SIZE))
            out, err = self.__process(msg)
            output = pickle.dumps((out, err), pickle.HIGHEST_PROTOCOL)
            conn.sendall(struct.pack('I', len(output)))
            conn.sendall(output)
        except Exception as ex:  # pylint: disable=broad-except
            self.__logger.error('Failed to process request from mgmt. client: '
                                '%s', ex)

    def run(self):
        """ Start the mgmt server
        """
        try:
            os.remove(self.__uds_file)
        except OSError:
            if os.path.exists(self.__uds_file):
                raise
        try:
            self.__socket.bind(self.__uds_file)
        except Exception as ex:  # pylint: disable=broad-except
            raise RuntimeError('Unable to bind to mgmt socket %s: %s' %
                               (self.__uds_file, ex))
        self.__socket.listen(self.__concurrency)
        eventlet.serve(self.__socket,
                       self.__handle_msg,
                       concurrency=self.__concurrency)


class MgmtClient(socket.socket):
    """A utility uses the client class to send a message to the daemon
    with a request.
    """
    __BUF_SIZE = 2 * 1024

    def __init__(self, uds_file):
        try:
            socket.socket.__init__(self, socket.AF_UNIX, socket.SOCK_STREAM)
            self.connect(uds_file)
        except socket.error, (errno, string):
            msg = ('Unable to connect to daemon on socket %s [%d]: %s' %
                   (uds_file, errno, string))
            raise RuntimeError(msg)

    def sendobj(self, msgobj):
        """ Serializes and sends a request to the mgmt server. Deserializes
        and returns the response.
        """
        msg = pickle.dumps(msgobj, pickle.HIGHEST_PROTOCOL)
        self.sendall(msg)
        size = int(struct.unpack('I', self.recv(4))[0])
        read_bytes = 0
        resp = ""
        while read_bytes < size:
            resp += self.recv(self.__BUF_SIZE)
            read_bytes = len(resp)

        out, err = pickle.loads(resp)
        return out, err
