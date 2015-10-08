=======
vxrdctl
=======

-----------------------------------------------------------
Inspection of the registration daemon for VXLAN deployments
-----------------------------------------------------------

:Manual section: 8


SYNOPSIS
========
| vxrdctl -h
| vxrdctl [-u UDS_FILE] [-j] <command> [<args>]


DESCRIPTION
===========

vxrdctl is used to inspect the VXLAN registration daemon's configuration.

The registration daemon ``vxrd(8)`` is a process that periodically
registers VTEPs with the service node ``vxsnd(8)`` to keep the
VTEP endpoint membership active at the service node.


OPTIONS
=======

The following options are recognized:

-h, --help
  Print usage and exit

-u UDS_FILE
  Unix domain socket of the registration daemon [default: /var/run/vxrd.sock]

-j
  Prints the result as json string


COMMANDS
========

The vxrdctl utility provides the following commands:

get config [<parameter>]
  Displays vxrd's runtime configuration. Providing a parameter prints a
  single configuration option.

peers
  Shows the list of VTEP peers reported back by the service node. This command
  is only available in head end replication mode.

vxlans
  Shows the current set of VXLANS the registration daemon has reported to the
  service node.


SEE ALSO
========
``vxrd``\(8)

http://tools.ietf.org/id/draft-mahalingam-dutt-dcops-vxlan-00.txt
