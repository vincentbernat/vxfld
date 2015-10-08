ifupdown2 addon for vxfld
=========================
ifupdown2 is an alternate implementation of debian's network interface manager
ifupdown. It provides the required infrastructure to parse, schedule and manage
interface configuration. Installing the vxfld addon for ifupdown2 allows you
to manage the registration daemon's configuration from your
``/etc/network/interfaces`` file.

Installation
------------

Follow the instructions on https://github.com/CumulusNetworks/ifupdown2/
to replace ifupdown with ifupdown2.

Copy the vxfld addon from your root vxfld directory to the ifupdown2 addons
directory by executing::

  cp ifupdown2/vxrd.py /usr/share/ifupdownaddons/

Finally, add the following lines to ``/var/lib/ifupdownaddons/addons.conf``::

  post-up,vxrd
  pre-down,vxrd

Examples
--------

To set the registration daemon's src and service node IP addresses, add the
following lines to the loopback stanza::

  auto lo
  iface lo
    vxrd-src-ip 10.2.1.1
    vxrd-svcnode-ip 10.2.1.3

This equivalent to setting the following options in vxrd.conf::

  [common]
  src_ip = 10.2.1.1
  svcnode_ip = 10.2.1.3
