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
# cgroups Management Daemon Process Handler for Ruby on Rails applications running under an Apache /
# Passenger server.
#
# To use this file, add "from rails_handler import RailsHandler" and "rh = RailsHandler()" to
# cgroupsd_handlers.py
#
# If making changes to this file, relevant documentation can be found in the comments in
# example_handler.py and at the following sites:
# cgroups parameters: https://www.kernel.org/doc/Documentation/cgroups/
# cgroupspy: https://github.com/cloudsigma/cgroupspy
# psutil.Process: http://pythonhosted.org/psutil/#process-class
#

# Limit on RSS memory size per cgroup, in MB
memory_limit = 2*1024+256  # 2.25GB
# When using the "smart" spawn method, Passenger can deadlock if a spawner process is killed at an
# inopportune time, so we move workers to a child cgroup that has a lower memory limit, such that
# workers are more likely to be killed than spawners.
workers_memory_limit = 2*1024  # 2GB

# This is used to classify processes spawned by "Passenger core" in Passenger 5,
# "PassengerHelperAgent" in Passenger 4.  It should be set to True if using the Passenger 4/5
# "smart" spawn method, or False if using the Passenger 4/5 "direct" or "conservative" spawn
# methods.
# For Passenger 3, only the "smart" spawn method is currently supported.  (See the comments below.)
using_smart_spawner = False



from base_handler import BaseHandler

import logging
import re
import psutil
import os
from cgroupspy.utils import split_path_components

class RailsHandler(BaseHandler):

  def __init__(self):
    self.__logger = logging.getLogger(__name__)

    # All new cgroups will be created under a base cgroup named 'RoR'
    self.base_cgroup = 'RoR'
    super(RailsHandler, self).__init__(subsystems=['memory'], base_cgroups=[self.base_cgroup])

    self.worker_regex = re.compile(r'^(?:Passenger (?:Rack|Ruby)App|Rails): (\S+)')
    self.spawner_regex = re.compile(r'^Passenger (?:AppPreloader|ApplicationSpawner): (\S+)')
    self.p3_spawner_regex = re.compile(r'^Passenger ApplicationSpawner: (\S+)')


  def get_process_cgroups(self, pid, proc, **event_args):

    # Established spawner and worker processes running under Passenger are easy to identify and
    # associate with individual Rails applications using proc.cmdline():
    # * Passenger 5 "smart" spawners use "Passenger AppPreloader: <app path>"
    # * Passenger 5 workers use "Passenger RubyApp: <app path>"
    # * Passenger 4 "smart" spawners use "Passenger AppPreloader: <app path>"
    # * Passenger 4 workers use "Passenger RackApp: <app path>"
    # * Passenger 3 "smart" spawners use "Passenger ApplicationSpawner: <app path>"
    # * Passenger 3 workers use "Rails: <app path>"
    # * Other Passenger helper processes use names without colons, such as "PassengerWatchdog",
    #   "PassengerHelperAgent", and "Passenger spawn server"
    #
    # Unfortunately, when handling new processes, Passenger generally will not change proc.cmdline()
    # to the above values until after we have processed all of the relevant 'fork' and 'exec'
    # events, so we must find other ways to identify new processes and associate them with
    # individual Rails applications.
    #
    # To start a new process (either a spawner or a worker), Passenger always forks an existing
    # process.  When using a "smart" spawn method, an established spawner is forked to start a new
    # worker.  When starting a spawner or using the "direct" or "conservative" spawn method,
    # "Passenger core" (Passenger 5), "PassengerHelperAgent" (Passenger 4), or
    # "Passenger spawn server" (Passenger 3) is forked.  After forking, Passenger execs a series of
    # bash and ruby commands, which repeatedly changes proc.cmdline() to various bash/ruby commands
    # that are hard to identify and do not include the app path.  The last of these commands is
    # always a ruby process (that does not initially include the app path in proc.cmdline()).
    # proc.cmdline() is then updated some time after the last ruby process is exec'd.
    # In Passenger 5 and Passenger 4, an IN_PASSENGER=1 environment variable is set and the current
    # working directory is changed to the app's path before the last ruby process is exec'd.
    # In Passenger 3, there does not appear to be any way to obtain the app's path until
    # proc.cmdline() is changed or the process opens application files.
    #
    # So, we currently do the following to identify new Passenger 4/5 processes and associate them
    # with individual Rails applications:
    # * Check whether proc.name() contains "ruby".  If not, the process isn't relevant.
    # * Check proc.cmdline() for an established worker string.  This will take care of established
    #   worker processes.
    # * Check proc.parent().cmdline() for an established spawner string.  This will take care of new
    #   worker processes when using the "smart" spawn method.
    # * Check proc.cmdline() for an established spawner string.  This will take care of established
    #   spawner processes.
    # * Check proc.parent().cmdline() for "Passenger core" or "PassengerHelperAgent" and check for
    #   an IN_PASSENGER=1 environment variable.  If present, read the process's working directory as
    #   the app path.  This will take care of new spawner processes and new worker processes when
    #   using the "direct" spawn method.  Note that we cannot distinguish between spawner and worker
    #   processes in this case, so all matching processes are treated as spawners if
    #   using_smart_spawner is True or workers if using_smart_spawner is False.
    #
    # For Passenger 3, we currently do the following:
    # * Check whether proc.name() is "ruby".  If not, the process isn't relevant.
    # * Check proc.cmdline() for an established worker string.  This will take care of established
    #   worker processes.
    # * Check proc.parent().cmdline() for an established spawner string.  This will take care of new
    #   worker processes when using the "smart" spawn method.
    # * Check proc.cmdline() for an established spawner string.  This will take care of established
    #   spawner processes.
    # * If proc.parent().cmdline() is found to contain an established spawner string then assign
    #   cgroups to the parent process.  This will take care of new spawners after they have become
    #   established.
    # Note that new workers are immediately assigned to cgroups when using a "smart" spawn method,
    # but new spawners are not assigned to cgroups until after they have forked their first worker.
    # We currently do not support assigning cgroups to new workers when using the "conservative"
    # spawn method.  There are a few ways we could add support for those:
    # * Add a "cmdline" proc event to the kernel, similar to the existing "comm" proc event.
    # * Modify Passenger or each Rails application to trigger an event that we can capture after
    #   proc.cmdline() has changed.  Maybe change the process name in addition to cmdline to trigger
    #   a "comm" proc event, or just fork a new process.
    # * Check proc.parent().cmdline() for "Passenger spawn server", then start a polling loop or
    #   timer in a background thread to wait for the proc.cmdline() changes.
    # * Periodically iterate through the process list and assign established workers to cgroups.

    # Identify relevant process and obtain the associated app path
    # Grab proc.name()
    try:
      proc_name = proc.name()
    except psutil.NoSuchProcess:
      self.__logger.debug('PID {0} exited before it could be processed'.format(pid))
      return True
    # Check whether proc.name() is "ruby"
    if proc_name != 'ruby': return False
    # Grab proc.cmdline() and proc.parent.cmdline()
    try:
      proc_cmdline = proc.cmdline()
      if len(proc_cmdline) == 0: proc_cmdline = ''
      else: proc_cmdline = proc_cmdline[0]
      parent_pid = proc.ppid()
      proc_parent = proc.parent()
      if proc_parent:
        proc_parent_cmdline = proc_parent.cmdline()
        if len(proc_parent_cmdline) == 0: proc_parent_cmdline = ''
        else: proc_parent_cmdline = proc_parent_cmdline[0]
      else: proc_parent_cmdline = ''
    except psutil.NoSuchProcess:
      self.__logger.debug('PID {0} exited before it could be processed'.format(pid))
      return True
    self.__logger.debug('PID {0} is a ruby process with cmdline "{1}" and parent PID {2} with cmdline "{3}"'.format(pid, proc_cmdline, parent_pid, proc_parent_cmdline))
    # Check proc.cmdline() for an established worker string
    match = self.worker_regex.match(proc_cmdline)
    if match:
      is_worker = True
      app_path = match.group(1)
      self.__logger.debug('PID {0} is an established worker'.format(pid))
    else:
      # Check proc.parent().cmdline() for an established spawner string
      match = self.spawner_regex.match(proc_parent_cmdline)
      if match:
        is_worker = True
        app_path = match.group(1)
        self.__logger.debug('PID {0} is a new worker forked from an established spawner'.format(pid))
      else:
        # Check proc.cmdline() for an established spawner string
        match = self.spawner_regex.match(proc_cmdline)
        if match:
          is_worker = False
          app_path = match.group(1)
          self.__logger.debug('PID {0} is an established spawner'.format(pid))
        # Check proc.parent().cmdline() for "Passenger core" or "PassengerHelperAgent" and check for
        # an IN_PASSENGER=1 environment variable
        elif proc_parent_cmdline == 'Passenger core' or proc_parent_cmdline == 'PassengerHelperAgent':
          try:
            env_file = open(os.path.join('/proc', str(pid), 'environ'))
            env = env_file.read().split('\0')
            env_file.close()
          except IOError as e:
            self.__logger.debug('Error reading /proc/{0}/environ, PID {1} probably exited before we read the file: {2}'.format(pid, pid, e))
            return True
          if 'IN_PASSENGER=1' not in env:
            self.__logger.debug('PID {0} does not appear to be a relevant Rails process (No INPASSENGER=1 environment variable)'.format(pid))
            return False
          is_worker = not using_smart_spawner
          self.__logger.debug('PID {0} is a new Passenger 4 spawner or worker'.format(pid))
          try:
            app_path = proc.cwd()
          except psutil.NoSuchProcess:
            self.__logger.debug('PID {0} exited before it could be processed'.format(pid))
            return True
        # No match, this process is not relevant
        else:
          self.__logger.debug('PID {0} does not appear to be a relevant Rails process'.format(pid))
          return False

    # If the parent process is an established Passenger 3 spawner, assign cgroups to it.
    match = self.p3_spawner_regex.match(proc_parent_cmdline)
    if match:
      parent_app_path = match.group(1)
      try:
        proc_parent_username = proc_parent.username()
      except psutil.NoSuchProcess:
        self.__logger.debug('PID {0} exited before it could be processed'.format(pid))
        return True
      cgroups = self._get_app_cgroups(parent_app_path, proc_parent_username, False)
      self.__logger.debug('Assigning established Passenger 3 spawner PID {0} ({1}) to cgroups {2}'.format(parent_pid, proc_parent_cmdline, cgroups))
      self.config_cgroups(cgroups)
      self.assign_process_cgroups(pid=parent_pid, proc=proc_parent, cgroups=cgroups)

    try:
      proc_username = proc.username()
    except psutil.NoSuchProcess:
      self.__logger.debug('PID {0} exited before it could be processed'.format(pid))
      return True
    return self._get_app_cgroups(app_path, proc_username, is_worker)


  def _get_app_cgroups(self, path, username, is_worker):

    # If the app path contains "application_home", then assume the app was deployed using capistrano
    # and use the parent directory name as the application name.  Otherwise use the last path
    # component as the application name.
    path_components = split_path_components(path)
    try: app_home_idx = path_components.index('application_home')
    except: app_home_idx = 0
    app_name = path_components[app_home_idx-1]

    # Return the cgroups that the process should be assigned to:
    # /<subsystem>/RoR/<username>/<app name>[/workers]
    if is_worker: cgroup_name = os.path.join(username, app_name, 'workers')
    else: cgroup_name = os.path.join(username, app_name)
    return [(subsystem, self.base_cgroup, cgroup_name) for subsystem in self.subsystems]


  def init_cgroup(self, cgroup_node, new_cgroup):
    super(RailsHandler, self).init_cgroup(cgroup_node, new_cgroup)

    if cgroup_node.controller_type == 'memory':
      if cgroup_node.name == 'workers' : mem_limit = workers_memory_limit
      else: mem_limit = memory_limit
      if new_cgroup or cgroup_node.controller.limit_in_bytes != mem_limit*1048576:
        self.__logger.info('Setting memory.limit_in_bytes={0}M on {1}'.format(mem_limit, cgroup_node.full_path))
        cgroup_node.controller.limit_in_bytes = mem_limit*1048576
