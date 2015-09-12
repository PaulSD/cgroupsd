#!/usr/bin/env python

#
# Copyright 2015 Paul Donohue <cgroupsd@PaulSD.com>
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
# cgroups Management Daemon Base Process Handler
#
# This class uses cgroupspy to implement basic / abstract functionality for the handler functions
# described in the comments in cgroupsd_listener.py.  It is intended to be extended by other classes
# which will customize its behavior for specific use cases.
#
# Prerequisites:
# cgroupspy : `sudo apt-get install python-pip` or `sudo yum install python-pip` then
#             `sudo pip install git+https://github.com/cloudsigma/cgroupspy.git`
#
# See etc/example_handler.py for example usage.
#
# cgroupspy documentation: https://github.com/cloudsigma/cgroupspy
#
# According to the cgroups and systemd maintainers, the long-term plan is for systemd to take
# exclusive control of the cgroups interface in the kernel.  When that happens, applications will
# need to manipulate cgroups through systemd APIs instead of kernel interfaces.  Unfortunately, as
# of early 2015, the systemd APIs for cgroup management are very incomplete: cgroups can only be
# created when processes are started by systemd itself, and processes cannot be moved between
# cgroups after they have been spawned.  Thus we cannot preemptively use the systemd APIs yet and
# we must continue using the kernel interfaces for now.  Unfortunately that means that this class
# and any classes that extend it may require a significant rewrite when systemd takes over cgroups.
#



import cgroupsd_listener

from cgroupspy import trees
from cgroupspy.utils import split_path_components

import logging
import os
import stat
import psutil
import errno
import signal
import syslog
from datetime import datetime

# /sys/fs/cgroup/ doesn't seem to be available in RHEL6, so use /cgroup/ instead
import platform
cgroups_root_path = '/sys/fs/cgroup/'
if 'Red Hat' in platform.linux_distribution()[0] and platform.linux_distribution()[1].startswith('6'):
  cgroups_root_path = '/cgroup/'

def _cur_perms(path):
  return stat.S_IMODE(os.stat(path).st_mode)

class BaseHandler(object):

  # Parameters:
  # subsystems : An optional list of subsystems to be mounted and loaded into the cgroupspy tree.
  #   If not specified, all currently mounted subsystems will be loaded, but no new subsystems will
  #   be mounted.
  # base_cgroups : An optional list of base cgroups that should be created and loaded into the
  #   cgroupspy tree.  If not specified, all existing cgroups will be loaded, but no new cgroups
  #   will be created.
  # cgroups_perms : Permissions to be set on each base cgroup specified with base_cgroups and each
  #   path component of any cgroups created under the specified base_cgroups.  Use None to skip
  #   setting permissions on these cgroups.  Permissions may be specified using octal notation
  #   (0o755) or using the constants from the stat module
  #   (stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR|stat.S_IRGRP|stat.S_IXGRP|stat.S_IROTH|stat.S_IXOTH).
  def __init__(self, subsystems=[], base_cgroups=[], cgroups_perms=0o755):
    self.__logger = logging.getLogger(__name__)

    # Mount any subsystems that are not already mounted
    trees.bootstrap(root_path=cgroups_root_path, subsystems=subsystems)
    # This will create the specified base_cgroups under each subsystem if they don't already exist
    self.cgroups_tree = trees.Tree(root_path=cgroups_root_path, groups=subsystems, sub_groups=base_cgroups)

    self.subsystems = subsystems or [ node.name for node in self.cgroups_tree.children ]
    self.base_cgroups = base_cgroups
    self.cgroups_perms = cgroups_perms

    # Set up cleanup parameters
    # Extending classes can override this in their __init__() after calling super().__init__()
    self.cleanup_interval = 30  # minutes
    self.last_cleanup = datetime.min
    self.cleanup_nodes = [
     self.cgroups_tree.get_node_by_path(os.path.join('/', subsystem, base_cgroup))
     for base_cgroup in base_cgroups for subsystem in subsystems]

    self.initialized_cgroups = {}

    # Configure (or reconfigure) the subsystems
    for subsystem in subsystems:
      self.config_subsystem(self.cgroups_tree.get_node_by_path(os.path.join('/', subsystem)))

    # Configure (or reconfigure) the base_cgroups
    for subsystem in self.subsystems:
      for base_cgroup in base_cgroups:
        path = os.path.join('/', subsystem)
        depth = 1
        for path_component in split_path_components(base_cgroup)[0:-1]:
          path = os.path.join(path, path_component)
          self.config_base_cgroup_parent(self.cgroups_tree.get_node_by_path(path), depth)
          self.initialized_cgroups[path] = True
          depth += 1
        path = os.path.join('/', subsystem, base_cgroup)
        self.config_base_cgroup(self.cgroups_tree.get_node_by_path(path))
        self.initialized_cgroups[path] = True

    # Register callbacks with cgroupsd_listener
    cgroupsd_listener.handlers['process'] += self.handle_process
    cgroupsd_listener.handlers['thread'] += self.handle_thread
    cgroupsd_listener.handlers['cleanup'] += self.handle_cleanup

  # This may be called to unregister the handler from cgroupsd_listener
  def unregister(self):
    cgroupsd_listener.handlers['process'] -= self.handle_process
    cgroupsd_listener.handlers['thread'] -= self.handle_thread
    cgroupsd_listener.handlers['cleanup'] -= self.handle_cleanup

  # This may be overridden to configure (or reconfigure) each of the subsystems specified in the
  # subsystems parameter to __init__().  However, configuring the subsystems themselves is generally
  # not recommended as any changes made at the subsystem level will affect all processes and may
  # result in unexpected behavior.  If the subsystem parameter was not provided to __init__() then
  # this will not be called.  The default implementation sets the permissions on each subsystem to
  # 0o755.
  def config_subsystem(self, cgroup_node):
    if _cur_perms(cgroup_node.full_path) != 0o755:
      self.__logger.info('Setting permissions on {0}'.format(cgroup_node.full_path))
      os.chmod(cgroup_node.full_path, 0o755)

  # This may be overridden to configure (or reconfigure) each parent cgroup (each parent path
  # component) of each of the cgroups specified in the base_cgroups parameter to __init__().  Care
  # must be taken to avoid making conflicting changes if these parent cgroups are shared by multiple
  # handler classes.  If the base_cgroups parameter was not provided to __init__() then this will
  # not be called.  The depth parameter is a 1-indexed integer indicating the depth of the path
  # component.  For example, given a base_cgroups parameter of ['a/b/c'], this would be called
  # twice: For 'a' with depth=1, and for 'a/b' with depth=2.  config_base_cgroup() would also be
  # called once to configure 'a/b/c'.  The default implementation sets the permissions on each
  # parent cgroup to 0o755.
  def config_base_cgroup_parent(self, cgroup_node, depth):
    if _cur_perms(cgroup_node.full_path) != 0o755:
      self.__logger.info('Setting permissions on {0}'.format(cgroup_node.full_path))
      os.chmod(cgroup_node.full_path, 0o755)

  # This may be overridden to configure (or reconfigure) each of the cgroups specified in the
  # base_cgroups parameter to __init__().  If the base_cgroups parameter was not provided to
  # __init__() then this will not be called.  The default implementation sets the permissions on
  # each parent cgroup to the value of the cgroups_perms parameter provided to __init__(), and sets
  # memory.use_hierarchy=1 and memory.move_charge_at_immigrate=3 if the cgroup is under the memory
  # subsystem.
  def config_base_cgroup(self, cgroup_node):
    if self.cgroups_perms and _cur_perms(cgroup_node.full_path) != self.cgroups_perms:
      self.__logger.info('Setting permissions on {0}'.format(cgroup_node.full_path))
      os.chmod(cgroup_node.full_path, self.cgroups_perms)
    if cgroup_node.controller_type == 'memory':
      if not cgroup_node.controller.use_hierarchy:
        self.__logger.info('Setting memory.use_hierarchy=1 on {0}'.format(cgroup_node.full_path))
        try: cgroup_node.controller.use_hierarchy = True
        # This may be thrown if the cgroup already includes nested cgroups,
        # but that shouldn't be a fatal error
        except IOError: self.__logger.exception('Error setting memory.use_hierarchy:')
      move = cgroup_node.controller.move_charge_at_immigrate
      if not move[0] or not move[1]:
        self.__logger.info('Setting memory.move_charge_at_immigrate=3 on {0}'.format(cgroup_node.full_path))
        cgroup_node.controller.move_charge_at_immigrate = [True, True]

  # This calls get_process_cgroups(), then passes the return value to config_cgroups() and
  # assign_process_cgroups().
  def handle_process(self, **args):
    pid = args['pid']
    proc = args['proc']
    cgroups = self.get_process_cgroups(**args)
    if isinstance(cgroups, bool): return cgroups

    try:
      proc_name = proc.name()
      proc_uid = proc.uids().real
    except psutil.NoSuchProcess:
      self.__logger.debug('PID {0} exited before it could be processed'.format(pid))
      return True
    self.__logger.debug('Assigning PID {0} (UID {1}: {2}) to cgroups {3}'.format(pid, proc_uid, proc_name, cgroups))

    self.config_cgroups(cgroups=cgroups, init_existing=args['event_args'].get('first_sync', False))
    self.assign_process_cgroups(cgroups=cgroups, **args)
    return True

  # This assigns the specified process and all of its associated threads to the specified cgroups.
  # cgroups should be specified in the format returned by get_process_cgroups() or
  # get_thread_cgroups().
  def assign_process_cgroups(self, pid, proc, cgroups, **args):
    try:
      proc_name = proc.name()
      proc_uid = proc.uids().real
    except psutil.NoSuchProcess:
      self.__logger.debug('PID {0} exited before it could be processed'.format(pid))
      return
    for cgroup in cgroups:
      path = os.path.join('/', *cgroup)
      cgroup_node = self.cgroups_tree.get_node_by_path(path)
      if pid not in cgroup_node.controller.procs:
        self.__logger.info('Moving PID {0} (UID {1}: {2}) to cgroup {3}'.format(pid, proc_uid, proc_name, path))
        try: cgroup_node.controller.procs = pid
        except IOError as e:
          err_num, err_str = e.args
          if cgroup_node.controller_type == 'memory' and \
             (err_num == errno.ENOMEM or err_num == errno.ENOSPC):
            try:
              proc_meminfo = proc.memory_info_ex()
              proc_mem = (proc_meminfo.rss - proc_meminfo.shared)/1048576
              cgroup_usage = cgroup_node.controller.usage_in_bytes/1048576
              cgroup_limit = cgroup_node.controller.limit_in_bytes/1048576
              self.__logger.warn('Killing PID {0} (UID {1}: {2}) because it is using more memory ({3}MB) than is available ({4}MB used, {5}MB limit) in cgroup {6}'.format(pid, proc_uid, proc_name, proc_mem, cgroup_usage, cgroup_limit, path))
              os.kill(pid, signal.SIGKILL)
              syslog.openlog(ident='cgroupsd', facility=syslog.LOG_KERN)
              syslog.syslog('Killed PID {0} (UID {1}: {2}) because it was using more memory ({3}MB) than was available ({4}MB used, {5}MB limit) in cgroup {6}'.format(pid, proc_uid, proc_name, proc_mem, cgroup_usage, cgroup_limit, path))
              syslog.syslog('Memory cgroup stats for {0} : {1}'.format(path, ' '.join(['{0}:{1}KB'.format(k,v/1024) for (k,v) in cgroup_node.controller.stat.iteritems()])))
              syslog.syslog('Processes in cgroup {0} :'.format(path))
              syslog.syslog('    PID  Mem (MB)    UID  Process')
              for pid in cgroup_node.controller.procs:
                try:
                  gproc = psutil.Process(pid)
                  gproc_name = gproc.name()
                  gproc_uid = gproc.uids().real
                  gproc_meminfo = gproc.memory_info_ex()
                  gproc_mem = (gproc_meminfo.rss - gproc_meminfo.shared)/1048576
                  syslog.syslog('  {0:>5}  {1:>8}  {2:>5}  {3}'.format(pid, gproc_mem, gproc_uid, gproc_name))
                except psutil.NoSuchProcess: continue
            except psutil.NoSuchProcess:
              self.__logger.warn('PID {0} (UID {1}: {2}) vanished before we could kill it because it was using more memory than was available in cgroup {3}'.format(pid, proc_uid, proc_name, path))
          else:
            self.__logger.warn('Error moving PID {0} (UID {1}: {2}) to cgroup {3}: {4}'.format(pid, proc_uid, proc_name, path, e))
      else:
        self.__logger.debug('PID {0} (UID {1}: {2}) is already in cgroup {3}'.format(pid, proc_uid, proc_name, path))

  # This should be overridden to identify processes (thread group leaders) that are relevant to this
  # handler and to assign cgroups to those processes.
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
  # name.  If the subsystems parameter was provided to __init__() then the specified subsystem name
  # must have been present in the specified subsystems parameter.  Otherwise, any valid subsystem
  # may be specified.  If the base_cgroups parameter was provided to __init__() then the specified
  # base name must have been present in the specified base_cgroups parameter.  Otherwise, '' (an
  # empty string) or any other valid cgroup may be specified.  config_cgroups() will be called to
  # reconfigure or create and configure the path components of the specified cgroup name.
  # The default implementation simply returns False.
  # See the comments in cgroupsd_listener.py for the behavior if both get_process_cgroups() and
  # get_thread_cgroups() are overridden.
  def get_process_cgroups(self, pid, proc, **event_args):
    return False

  # This calls get_thread_cgroups(), then passes the return value to config_cgroups() and
  # assign_thread_cgroups().
  def handle_thread(self, **args):
    pid = args['pid']
    tid = args['tid']
    tproc = args['tproc']
    cgroups = self.get_thread_cgroups(**args)
    if isinstance(cgroups, bool): return cgroups

    try:
      tproc_name = tproc.name()
      tproc_uid = tproc.uids().real
    except psutil.NoSuchProcess:
      self.__logger.debug('PID {0} TID {1} exited before it could be processed'.format(pid, tid))
      return True
    self.__logger.debug('Assigning PID {0} TID {1} (UID {2}: {3}) to cgroups {4}'.format(pid, tid, tproc_uid, tproc_name, cgroups))

    self.config_cgroups(cgroups=cgroups, init_existing=args['event_args'].get('first_sync', False))
    self.assign_thread_cgroups(cgroups=cgroups, **args)
    return True

  # This assigns the specified thread to the specified cgroups.  cgroups should be specified in the
  # format returned by get_process_cgroups() or get_thread_cgroups().
  def assign_thread_cgroups(self, tid, tproc, pid, proc, **args):
    try:
      tproc_name = tproc.name()
      tproc_uid = tproc.uids().real
    except psutil.NoSuchProcess:
      self.__logger.debug('PID {0} TID {1} exited before it could be processed'.format(pid, tid))
      return
    for cgroup in cgroups:
      path = os.path.join('/', *cgroup)
      cgroup_node = self.cgroups_tree.get_node_by_path(path)
      if tid not in cgroup_node.controller.tasks:
        self.__logger.info('Moving PID {0} TID {1} (UID {2}: {3}) to cgroup {4}'.format(pid, tid, tproc_uid, tproc_name, path))
        try: cgroup_node.controller.tasks = tid
        except IOError as e:
          # Unlike handle_process(), we do not need to check for ENOMEM here since
          # memory.move_charge_at_immigrate does not apply when moving threads.
          self.__logger.warn('Error moving PID {0} TID {1} (UID {2}: {3}) to cgroup {4}: {5}'.format(pid, tid, tproc_uid, tproc_name, path, e))
      else:
        self.__logger.debug('PID {0} TID {1} (UID {2}: {3}) is already in cgroup {4}'.format(pid, tid, tproc_uid, tproc_name, path))

  # This should be overridden to identify threads that are relevant to this handler and to assign
  # cgroups to those threads.
  # The "tid" argument is the PID of the thread, and the "pid" argument is the PID of the thread
  # group leader.  For threads that are thread group leaders, tid == pid.  The "tproc" and "proc"
  # arguments are psutil.Process objects for the specified "tid" and "pid" respectively.  See
  # http://pythonhosted.org/psutil/#process-class for documentation.  The "event_args" argument is
  # the arguments dict associated with the proc_events or reliable_proc_events event that triggered
  # this call.
  # Note that because this function is (indirectly) called when process events are triggered, any
  # new processes or threads spawned by this function will trigger additional calls to this
  # function.  To avoid infinite loops, this function must be careful to avoid spawning new
  # processes or threads.
  # This should return False if the specified process is not relevant to this handler, or a list of
  # tuples representing cgroups that the thread should be assigned to.  Each cgroup tuple should
  # consist of a subsystem name, a base name, and a cgroup name.  If the subsystems parameter was
  # provided to __init__() then the specified subsystem name must have been present in the specified
  # subsystems parameter.  Otherwise, any valid subsystem may be specified.  If the base_cgroups
  # parameter was provided to __init__() then the specified base name must have been present in the
  # specified base_cgroups parameter.  Otherwise, '' (an empty string) or any other valid cgroup may
  # be specified.  config_cgroups() will be called to reconfigure or create and configure the path
  # components of the specified cgroup name.
  # The default implementation simply returns False.
  # See the comments in cgroupsd_listener.py for the behavior if both get_process_cgroups() and
  # get_thread_cgroups() are overridden.
  # If using the memory subsystem, note that memory.move_charge_at_immigrate only applies when
  # moving processes (thread group leaders) between cgroups, and does not apply to when moving
  # individual threads within a process.  See
  # https://www.kernel.org/doc/Documentation/cgroups/memory.txt for relevant documentation.
  def get_thread_cgroups(self, pid, proc, **event_args):
    return False

  # This accepts a list of cgroup tuples (in the format returned by get_process_cgroups() or
  # get_thread_cgroups()) and calls init_cgroup_parent(), init_cgroup(), reconfig_cgroup_parent(),
  # or reconfig_cgroup() for each cgroup path component included in the cgroup name value within
  # each cgroup tuple.  Path components included in the base name value within each cgroup tuple are
  # assumed to exist already.  If "init_existing" is True then init_cgroup_parent() or init_cgroup()
  # will be called for existing cgroups that have not already been encountered.
  def config_cgroups(self, cgroups, init_existing=False):
    if not init_existing:
      # This shouldn't be needed any more after we've reconfigured all of the existing cgroups
      self.initialized_cgroups = {}
    for cgroup in cgroups:
      path = os.path.join('/', cgroup[0], cgroup[1])
      cgroup_node = self.cgroups_tree.get_node_by_path(path)
      depth = 1
      for path_component in split_path_components(cgroup[2])[0:-1]:
        path = os.path.join(path, path_component)
        next_cgroup_node = self.cgroups_tree.get_node_by_path(path)
        if not next_cgroup_node:
          self.__logger.info('Creating cgroup {0}'.format(path))
          cgroup_node = cgroup_node.create_cgroup(path_component)
          self.init_cgroup_parent(cgroup_node, depth, new_cgroup=True)
        elif init_existing and self.initialized_cgroups.get(path, None) == None:
          cgroup_node = next_cgroup_node
          self.init_cgroup_parent(cgroup_node, depth, new_cgroup=False)
          self.initialized_cgroups[path] = True
        else:
          cgroup_node = next_cgroup_node
          self.reconfig_cgroup_parent(cgroup_node, depth)
        depth += 1
      path = os.path.join('/', *cgroup)
      next_cgroup_node = self.cgroups_tree.get_node_by_path(path)
      if not next_cgroup_node:
        self.__logger.info('Creating cgroup {0}'.format(path))
        cgroup_node = cgroup_node.create_cgroup(os.path.basename(path))
        self.init_cgroup(cgroup_node, new_cgroup=True)
      elif init_existing and self.initialized_cgroups.get(path, None) == None:
        cgroup_node = next_cgroup_node
        self.init_cgroup(cgroup_node, new_cgroup=False)
        self.initialized_cgroups[path] = True
      else:
        cgroup_node = next_cgroup_node
        self.reconfig_cgroup(cgroup_node)

  # This may be overridden to initialize each parent cgroup (each parent path component of a cgroup,
  # not including base name path components) that is created by config_cgroups(), and to reconfigure
  # each existing parent cgroup that is encountered by config_cgroups() during the initial process
  # iteration when cgroupsd_listener is started.
  # Note that because this function is (indirectly) called when process events are triggered, any
  # new processes or threads spawned by this function may trigger additional calls to this
  # function.  To avoid infinite loops, this function must be careful to avoid spawning new
  # processes or threads.
  # The "depth" parameter is a 1-indexed integer indicating the depth of the path component.  For
  # example, given a new cgroup name of 'a/b/c' where 'a' does not already exist, this would be
  # called twice: For 'a' with depth=1, and for 'a/b' with depth=2.  init_cgroup() would also be
  # called once to configure 'a/b/c'.  The "new_cgroup" parameter will be True if this is being
  # called to initialize a new cgroup, or False if this is being called to reconfigure an existing
  # cgroup during the initial process iteration when cgroupsd_listener is started.
  # The default implementation sets the permissions on each parent cgroup to the value of the
  # cgroups_perms parameter provided to __init__(), and sets memory.use_hierarchy=1 and
  # memory.move_charge_at_immigrate=3 if the cgroup is under the memory subsystem.
  def init_cgroup_parent(self, cgroup_node, depth, new_cgroup):
    if self.cgroups_perms and _cur_perms(cgroup_node.full_path) != self.cgroups_perms:
      self.__logger.info('Setting permissions on {0}'.format(cgroup_node.full_path))
      os.chmod(cgroup_node.full_path, self.cgroups_perms)
    if cgroup_node.controller_type == 'memory':
      if new_cgroup or not cgroup_node.controller.use_hierarchy:
        self.__logger.info('Setting memory.use_hierarchy=1 on {0}'.format(cgroup_node.full_path))
        try: cgroup_node.controller.use_hierarchy = True
        # This may be thrown if the cgroup already includes nested cgroups,
        # but that shouldn't be a fatal error
        except IOError: self.__logger.exception('Error setting memory.use_hierarchy:')
      move = cgroup_node.controller.move_charge_at_immigrate
      if new_cgroup or not move[0] or not move[1]:
        self.__logger.info('Setting memory.move_charge_at_immigrate=3 on {0}'.format(cgroup_node.full_path))
        cgroup_node.controller.move_charge_at_immigrate = [True, True]

  # This may be overridden to reconfigure each existing parent cgroup (each parent path component of
  # a cgroup, not including base name path components) that is encountered by config_cgroups() after
  # the initial process iteration when cgroupsd_listener is started.
  # Note that because this function is (indirectly) called when process events are triggered, any
  # new processes or threads spawned by this function may trigger additional calls to this
  # function.  To avoid infinite loops, this function must be careful to avoid spawning new
  # processes or threads.
  # The depth parameter is a 1-indexed integer indicating the depth of the path component.  For
  # example, given an existing cgroup name of 'a/b/c', this would be called twice: For 'a' with
  # depth=1, and for 'a/b' with depth=2.  reconfig_cgroup() would also be called once to reconfigure
  # 'a/b/c'.  The default implementation does nothing.
  def reconfig_cgroup_parent(self, cgroup_node, depth):
    pass

  # This may be overridden to initialize each cgroup that is created by config_cgroups(), and to
  # reconfigure each existing cgroup that is encountered by config_cgroups() during the initial
  # process iteration when cgroupsd_listener is started.
  # Note that because this function is (indirectly) called when process events are triggered, any
  # new processes or threads spawned by this function may trigger additional calls to this
  # function.  To avoid infinite loops, this function must be careful to avoid spawning new
  # processes or threads.
  # The "new_cgroup" parameter will be True if this is being called to initialize a new cgroup, or
  # False if this is being called to reconfigure an existing cgroup during the initial process
  # iteration when cgroupsd_listener is started.
  # The default implementation sets the permissions on each cgroup to the value of the cgroups_perms
  # parameter provided to __init__(), and sets memory.use_hierarchy=1 and
  # memory.move_charge_at_immigrate=3 if the cgroup is under the memory subsystem.
  def init_cgroup(self, cgroup_node, new_cgroup):
    if self.cgroups_perms and _cur_perms(cgroup_node.full_path) != self.cgroups_perms:
      self.__logger.info('Setting permissions on {0}'.format(cgroup_node.full_path))
      os.chmod(cgroup_node.full_path, self.cgroups_perms)
    if cgroup_node.controller_type == 'memory':
      if new_cgroup or not cgroup_node.controller.use_hierarchy:
        self.__logger.info('Setting memory.use_hierarchy=1 on {0}'.format(cgroup_node.full_path))
        try: cgroup_node.controller.use_hierarchy = True
        # This may be thrown if the cgroup already includes nested cgroups,
        # but that shouldn't be a fatal error
        except IOError: self.__logger.exception('Error setting memory.use_hierarchy:')
      move = cgroup_node.controller.move_charge_at_immigrate
      if new_cgroup or not move[0] or not move[1]:
        self.__logger.info('Setting memory.move_charge_at_immigrate=3 on {0}'.format(cgroup_node.full_path))
        cgroup_node.controller.move_charge_at_immigrate = [True, True]

  # This may be overridden to reconfigure each existing cgroup that is encountered by
  # config_cgroups() after the initial process iteration when cgroupsd_listener is started.
  # Note that because this function is (indirectly) called when process events are triggered, any
  # new processes or threads spawned by this function may trigger additional calls to this
  # function.  To avoid infinite loops, this function must be careful to avoid spawning new
  # processes or threads.
  # The default implementation does nothing.
  def reconfig_cgroup(self, cgroup_node):
    pass

  # This recursively walks all children of each of the cgroups specified in the base_cgroups
  # parameter to __init__() and deletes any empty cgroups.  If the base_cgroups parameter was not
  # provided to __init__() then this will do nothing.
  # Note that any short-lived processes or threads spawned by this callback will trigger additional
  # calls to this callback.  To avoid infinite loops, this callback must be careful to avoid
  # spawning short-lived processes or threads.
  def handle_cleanup(self, **args):
    delta = datetime.utcnow() - self.last_cleanup
    if delta.days > 0 or delta.seconds > (self.cleanup_interval * 60):
      self.__logger.info('Cleaning up empty cgroups')
      self.last_cleanup = datetime.utcnow()
      for cgroup_node in self.cleanup_nodes:
        cgroup_node.delete_empty_children()
    return False
