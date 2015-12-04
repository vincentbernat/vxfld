========
vxsndctl
========

---------------------------------------------------------------
Administration of the service node daemon for VXLAN deployments
---------------------------------------------------------------

:Manual section: 8


SYNOPSIS
========
| vxsndctl -h
| vxsndctl [-u UDS_FILE] [-j] <command> [<args>]


DESCRIPTION
===========

vxsndctl is used to inspect and update the VXLAN service node daemon's
configuration and runtime state.

The service node daemon ``vxsnd(8)`` is a process that maintains a list of
VTEPs associated with each VXLAN. It synchronizes state between registration
daemons and can flood packets throughout a VXLAN on behalf of VTEPs.


OPTIONS
=======

The following options are recognized:

-h, --help
  Print usage and exit

-u UDS_FILE
  Unix domain socket of the service node daemon [default: /var/run/vxsnd.sock]

-j
  Prints the result as json string


COMMANDS
========

The vxsndctl utility provides the following commands:

fdb [<vni>]
  Displays the current set of addresses that the registration daemons have
  reported to the service node. Provide a VNI to print addresses for a
  specific VNI.

get config [<parameter>]
  Displays vxsnd's runtime configuration. Providing a parameter prints a
  single configuration option.

set config <parameter> [<value>]
  Updates the value of an option in vxsnd's runtime configuration. Only
  reloadable configuration options can be updated at runtime.

set debug (on | off)
  Enables or disables debug mode.

show [<detail>]
  Displays a snapshot of vxsnd's runtime configuration.


SEE ALSO
========
``vxsnd``\(8), ``vxrd``\(8)

http://tools.ietf.org/id/draft-mahalingam-dutt-dcops-vxlan-00.txt
