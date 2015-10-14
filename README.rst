*******************************
VXFLD: VXLAN BUM Flooding Suite
*******************************

VXFLD is a suite of tools that provides the ability to do VXLAN
BUM flooding using unicast instead of the traditional multicast.
This is accomplished using 2 components, `vxsnd`_ and `vxrd`_.

vxsnd provides the unicast BUM packet flooding and VTEP learning
capabilities while vxrd is a simple registration daemon designed to
register local VTEPs with a remote vxsnd daemon.

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
.. _vxsnd: https://github.com/CumulusNetworks/vxfld/blob/master/vxsnd.rst
.. _vxrd: https://github.com/CumulusNetworks/vxfld/blob/master/vxrd.rst
