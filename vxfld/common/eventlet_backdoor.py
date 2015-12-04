# Copyright (c) 2012 OpenStack Foundation.
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
""" This module provides functions used by eventlet's backdoor server.
"""
import gc
import pprint
import sys
import traceback

import eventlet.backdoor
import eventlet.debug
import eventlet.hubs
import greenlet


def _dont_use_this():
    """ Name says it all.
    """
    print 'Don\'t use this, just disconnect instead'


def _displayhook(val):
    """ The standard sys.displayhook will print the value of
    the last expression and set it to __builtin__._, which overwrites
    the __builtin__._ that gettext sets. Let's switch to using pprint
    since it won't interact poorly with gettext, and it's easier to
    read the output too.
    """
    if val is not None:
        pprint.pprint(val)


def _find_objects(instance_type):
    """ Find objects by type.
    """
    return [o for o in gc.get_objects() if isinstance(o, instance_type)]


def _print_greenthreads():
    """ Print tracebacks for all green threads.
    """
    # pylint: disable=no-member
    for i, green_thread in enumerate(_find_objects(greenlet.greenlet)):
        print i, green_thread
        traceback.print_stack(green_thread.gr_frame)
        print


def _print_nativethreads():
    """ Print tracebacks for all python threads.
    """
    # pylint: disable=protected-access
    for thread_id, stack in sys._current_frames().iteritems():
        print thread_id
        traceback.print_stack(stack)
        print


def initialize_if_enabled(backdoor_port):
    """ Launch eventlet's backdoor server.
    """
    backdoor_locals = {
        'exit': _dont_use_this,      # So we don't exit the entire process
        'quit': _dont_use_this,      # So we don't exit the entire process
        'fo': _find_objects,
        'pgt': _print_greenthreads,
        'pnt': _print_nativethreads,
        'spew': eventlet.debug.spew,
        'unspew': eventlet.debug.unspew,
        'fhl': eventlet.debug.format_hub_listeners
    }

    sys.displayhook = _displayhook
    eventlet.debug.hub_listener_stacks(state=True)
    eventlet.debug.hub_blocking_detection(state=True)
    eventlet.spawn_n(eventlet.backdoor.backdoor_server,
                     eventlet.listen(('localhost', backdoor_port)),
                     locals=backdoor_locals)
