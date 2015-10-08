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

To receive flood packets from a Replicating service node, a VTEP must
register the VXLANs it belongs to.  ``vxrd`` is a process to
periodically register with the service node ``vxsnd(8)`` to keep the
VTEP endpoint membership active at the service node.

OPTIONS
=======

-c, \--config FILE
  The config file to load.  Default is /etc/vxrd.conf

-d, --daemon
  Run as a daemon program

-D, --debug
  Set log level to debug


Configuration
=============

All the options above and additional configuration options can be
speficied in a configuration file, read at startup.  All the
configuration options and their defaults are specified in the default
config file */etc/vxrd.conf*.  Options specified on the command line
take precedence over options specified in the config file.



SEE ALSO
========
``ip-link``\(8), ``brctl``\(8), ``vxsnd``\(8)

http://tools.ietf.org/id/draft-mahalingam-dutt-dcops-vxlan-00.txt

