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

vxrdctl is used to inspect the VXLAN registration daemon's configuration and
runtime state.

The registration daemon ``vxrd(8)`` is a process that periodically
registers VTEPs with the service node ``vxsnd(8)`` to keep its VTEP membership
active.


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

peers [<vni>]
  Shows the list of VTEP peers reported back by the service node. This command
  is only available in head end replication mode.

show
  Displays a snapshot of vxrd's runtime configuration.

vxlans [<hrep>]
  Shows the current set of VXLANs the registration daemon has reported to the
  service node. Appending ``hrep`` to this command prints the HREP addresses
  from the bridge table when head end replication is enabled.


SEE ALSO
========
``vxrd``\(8)

http://tools.ietf.org/id/draft-mahalingam-dutt-dcops-vxlan-00.txt
