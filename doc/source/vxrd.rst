====
vxrd
====

-----------------------------------------
Registration daemon for VXLAN deployments
-----------------------------------------

:Manual section: 8


SYNOPSIS
========
vxrd [OPTIONS]


DESCRIPTION
===========

``vxrd`` is a process that periodically registers with the service node
``vxsnd(8)`` to keep its VTEP membership active. It also programs the bridge
table with the IP addresses of remote VTEPs when head end replication is
enabled.

OPTIONS
=======

-c, \--config FILE
  The config file to load.  Default is /etc/vxrd.conf

-d, \--daemon
  Run as a daemon program

-p, \--pidfile FILE
  The filename for the PID file. Default is /var/run/vxrd.pid

-u, \--udsfile FILE
  Unix domain socket for mgmt. interface. Default is /var/run/vxrd.sock

-D, --debug
  Set log level to debug


Configuration
=============

All the options above and additional configuration options can be
specified in a configuration file, read at startup.  All the
configuration options and their defaults are specified in the default
config file */etc/vxrd.conf*.  Options specified on the command line
take precedence over options specified in the config file.



SEE ALSO
========
``ip-link``\(8), ``brctl``\(8), ``vxsnd``\(8)

http://tools.ietf.org/id/draft-mahalingam-dutt-dcops-vxlan-00.txt

