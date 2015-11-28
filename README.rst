*******************************
VXFLD: VXLAN BUM Flooding Suite
*******************************

VXFLD is a suite of tools that provides the ability to do VXLAN broadcast,
unknown unicast, and multicast (BUM) flooding using unicast instead of the
traditional multicast. This is accomplished using 2 components, the service
node daemon (`vxsnd`_) and the registration daemon (`vxrd`_).

It supports the following modes of operation:

**Head-End replication**

In this mode, the node at the head-end of the VXLAN tunnel makes copies of
packets for each possible IP address at which the destination MAC address can
be found. These packets are then unicast to all VXLAN tunnel endpoints (VTEPs)
within the VXLAN segment. In addition to performing its registration function,
vxrd programs the bridge table with IP addresses of remote VTEPs in the
VXLAN segment, while vxsnd provides VTEP learning capabilities to the
registration daemons.

To enable head-end replication:

1. Set ``head_rep`` to ``True`` in vxrd's configuration file.
2. Clear the remote address for the VXLAN interface.

**Service Node Replication**

Use this mode to replicate VXLAN BUM packets at the service node when you
exceed the maximum VTEPs per VXLAN segment supported by the VXLAN driver.
vxsnd provides the unicast BUM packet flooding and VTEP learning
capabilities, and vxrd is responsible for registering local VTEPs with
the service node.

To enable service node replication:

1. Disable head end replication by setting ``head_rep`` to ``False`` in vxrd's
   configuration file.
2. Set the remote address for the VXLAN interface to the service node's IP
   address (``svcnode_ip`` in vxsnd's configuration file).
3. Set ``enable_vxlan_listen`` to ``True`` in vxsnd's configuration file to
   forward VXLAN data traffic on the service node.
   

Installation
============

Install using pip::

  pip install git+https://github.com/CumulusNetworks/vxfld.git

or install from source::

  python setup.py install

Building and installing man pages
=================================

Build the man pages::

  python setup.py build_sphinx

Once built, the man pages can be found under build/man/. To install them::

  mkdir /usr/local/man/man8
  install -g 0 -o 0 -m 0644 build/man/vx*.8  /usr/local/man/man8/
  gzip /usr/local/man/man8/vx*.8

Getting started
===============

Registration node
-----------------

Refer to the *Configuring the Registration Node* section in the
`LNV user guide`_. Launch the daemon by running::

  sudo /path/to/vxrd -d

or to run as non-sudo::

  /path/to/vxrd -d -p /path/to/vxrd.pid -u /path/to/vxrd.sock [ -c /path/to/vxrd.conf ]

Service node
------------

Refer to the *Configuring the Service Node* section in the
`LNV user guide`_. Launch the daemon by running::

  sudo /path/to/vxsnd -d

or to run as non-sudo::

  /path/to/vxsnd -d -p /path/to/vxsnd.pid -u /path/to/vxsnd.sock --no-flood [ -c /path/to/vxsnd.conf ]

Note: software replication requires root priveleges to bind to raw sockets;
--no-flood disables it.

Documentation
=============

Cumulus Networks `LNV user guide`_.

.. _LNV user guide: http://docs.cumulusnetworks.com/display/DOCS/Lightweight+Network+Virtualization+-+LNV
.. _vxrd: https://github.com/CumulusNetworks/vxfld/blob/master/doc/source/vxrd.rst
.. _vxsnd: https://github.com/CumulusNetworks/vxfld/blob/master/doc/source/vxsnd.rst
