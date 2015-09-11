#!/usr/bin/env python

#
# Copyright 2015 Paul Donohue <cgroupsd_handlers@PaulSD.com>
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program.  If
# not, see <http://www.gnu.org/licenses/>.
#

#
# cgroups Management Daemon Example Process Handler
#
# To use this file, add "from example_handler import ExampleHandler" and "eh = ExampleHandler()" to
# cgroupsd_handlers.py
#

#
# There are two ways you can implement a cgroupsd process handler.
#
# The first way, shown here, is to extend BaseHandler and override some of its functions to
# customize its behavior.  This should cover most common use cases with minimal coding.  See the
# comments in base_handler.py for additional documentation for the functions that are overridden
# below, and for additional functions that may be overridden.  BaseHandler uses cgroupspy to
# manipulate cgroups.  cgroupspy documentation can be found at:
# https://github.com/cloudsigma/cgroupspy
#
# The second way is to implement custom cgroupsd_listener callbacks, effectively replacing
# BaseHandler entirely.  This provides additional flexibility, but also requires additional coding.
# See the comments in cgroupsd_listener.py for documentation.  Handlers implemented in this manner
# may use any mechanism of their choosing to manipulate cgroups (cgroupsd_listener has no
# dependencies on cgroupspy).  However, as noted in the cgroupsd_listener documentation, you must be
# careful to ensure that your implementation does not cause new processes or threads to be spawned
# by the callbacks, or to ensure that those spawns do not cause infinite loops within the callbacks.
#

# Integer representing the relative shares of CPU assigned to each cgroup
cpu_shares = 100
# Limit on RSS memory size per cgroup, in MB
memory_limit = 200



from base_handler import BaseHandler

import logging
import re
import psutil
import os

class ExampleHandler(BaseHandler):

  def __init__(self):
    self.__logger = logging.getLogger(__name__)

    # All new cgroups will be created under a base cgroup named 'Example'
    self.base_cgroup = 'Example'
    super(ExampleHandler, self).__init__(subsystems=['cpu', 'memory'], base_cgroups=[self.base_cgroup])

    self.relevant_regex = re.compile(r'^(cgroups_test[a-zA-Z0-9_-]*)')


  # This will be called to identify processes (thread group leaders) that are relevant to this
  # handler and assign cgroups to those processes (and all of their associated threads).
  # The "proc" argument is a psutil.Process object for the specified "pid".  See
  # http://pythonhosted.org/psutil/#process-class for documentation.  The "event_args" argument is
  # the arguments dict associated with the proc_events or reliable_proc_events event that triggered
  # this call.
  # Note that because this function is (indirectly) called when process events are triggered, any
  # new processes spawned by this function will trigger additional calls to this function.  To avoid
  # infinite loops, this function must be careful to avoid spawning new processes.
  # This should return False if the specified process is not relevant to this handler, or a list of
  # tuples representing cgroups that the process (and all of its associated threads) should be
  # assigned to.  Each cgroup tuple should consist of a subsystem name, a base name, and a cgroup
  # name.
  # See get_thread_cgroups() in base_handler.py to handle threads individually.
  def get_process_cgroups(self, pid, proc, **event_args):
    # Some relevant fields in proc that you may want to use:
    # proc.name() : Command name as output by `ps -o comm`
    # proc.cmdline() : Command line as output by `ps -o args` (returned as a list, not a string)
    # proc.exe() : Executable path as pointed to by the /proc/<PID>/exe symlink
    # proc.cwd() : Current working directory
    # proc.username() : Username associated with the real UID
    # proc.uids().real : Real UID
    # proc.uids().effective : Effective UID
    # proc.parent() : A psutils.Process object for the parent process

    # If the process exits before we are done, calls to psutils.Process methods may fail.  To handle
    # that gracefully:
    try:
      proc_name = proc.name()
      proc_username = proc.username()
    except psutil.NoSuchProcess:
      self.__logger.debug('PID {0} exited before it could be processed'.format(pid))
      return True

    # Determine if the process is relevant to this handler
    match = self.relevant_regex.match(proc_name)
    if not match: return False

    # Return the cgroups that the process should be assigned to
    # (/<subsystem>/Example/<username>/<process name>)
    return [(subsystem, self.base_cgroup, os.path.join(proc_username, proc_name))
            for subsystem in self.subsystems]


  # This will be called to initialize any new (not already existing) cgroups, or to reconfigure any
  # existing but not previously encountered (since cgroupsd_listener was started) cgroups that were
  # assigned to a process by get_process_cgroups().
  # Note that because this function is (indirectly) called when process events are triggered, any
  # new processes or threads spawned by this function may trigger additional calls to this
  # function.  To avoid infinite loops, this function must be careful to avoid spawning new
  # processes or threads.
  # The "new_cgroup" parameter will be True if this is being called to initialize a new cgroup, or
  # False if this is being called to reconfigure an existing cgroup.
  # The super (BaseHandler) implementation sets the permissions on each parent cgroup to the value
  # of the cgroups_perms parameter provided to __init__(), and sets memory.use_hierarchy=1 and
  # memory.move_charge_at_immigrate=3 if the cgroup is under the memory subsystem.
  def init_cgroup(self, cgroup_node, new_cgroup):
    super(ExampleHandler, self).init_cgroup(cgroup_node, new_cgroup)

    # Documentation for cgroups parameters:
    # https://www.kernel.org/doc/Documentation/cgroups/
    if cgroup_node.controller_type == 'cpu':
      self.__logger.info('Setting cpu.shares={0} on {1}'.format(cpu_shares, cgroup_node.full_path))
      cgroup_node.controller.shares = cpu_shares
    elif cgroup_node.controller_type == 'memory':
      self.__logger.info('Setting memory.limit_in_bytes={0}M on {1}'.format(memory_limit, cgroup_node.full_path))
      cgroup_node.controller.limit_in_bytes = memory_limit*1048576
