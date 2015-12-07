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
""" This module provides the VXLAN packet class.
"""
import dpkt


class VXLAN(dpkt.Packet):
    """ VXLAN header parsing/editing.
    VLXAN per draft-mahalingam-dutt-dcops-vxlan-00.txt
    The packing is pretty funky, so the two fields that actually matter;
    the I flag and VNI are formed as properties (i and vni) in the constructor
    as opposed to the dpkt header formatter.
    """
    # pylint: disable=attribute-defined-outside-init
    __hdr__ = (
        ('flags', 'B', 0x08),
        ('r', '3s', '\x00' * 3),
        ('vni_r', 'I', 0x0),
    )

    @property
    def i(self):
        """ Returns the I flag bit from the VXLAN header.
        """
        return (self.flags >> 3) & 0x1

    @i.setter
    def i(self, i):
        """ Sets the I flag bit in the VXLAN header.
        """
        self.flags = ((self.flags & 0x08) | (i << 3))

    @property
    def vni(self):
        """ Returns the 24 bit VNI from the VXLAN header.
        """
        return (self.vni_r >> 8) & 0x00ffffff

    @vni.setter
    def vni(self, vni):
        """ Sets the 24 bit VNI in the VXLAN header.
        """
        self.vni_r = ((self.vni_r & 0x00ffffff) | (vni << 8))
