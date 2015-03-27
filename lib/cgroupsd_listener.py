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
# cgroups Management Daemon Linux Process Events Listener
#
# This module listens for events from the proc_events and reliable_proc_events modules and calls
# configured handler functions to create/configure cgroups and assign processes/threads to them as
# events are generated.
#
# Prerequisites:
# psutil (v2 or later) : `sudo apt-get install python-psutil` or
#                        `sudo yum install python-pip ; sudo pip install psutil`
# See the comments in libnl.py for additional prerequisites.
#
# Basic Usage:
# import cgroupsd_listener
# print('Do any initial cgroup setup/prep here')
# def handle_process(pid, proc, **args):
#   print('Create/configure new cgroups if needed')
#   print('Then assign the process to the relevant cgroup(s)')
# def handle_cleanup(**args):
#   print('Delete any cgroups that were created by handle_process() and are now empty')
# cgroupsd_listener.handlers['process'] = handle_process
# cgroupsd_listener.handlers['cleanup'] = handle_cleanup
# cgroupsd_listener.start()  # Should not be called until all handlers are registered
# ...
# cgroupsd_listener.stop()  # Optional
#
# Available handler callbacks:
# handlers['process'] -> callback(type='process', pid, proc, event_args)
#   This is called if a process (a thread group leader) may need to be reclassified into cgroups.
#   On start-up, this will be called repeatedly for each existing process.  During normal operation,
#   this will be called any time a process is created or replaced (via fork or exec), changes its
#   uid or gid, or changes its "comm" value (its command name as output by `ps -o comm`).  If
#   process events are lost or cannot be received, this may be called periodically for each existing
#   process.
#   When called, this callback should determine whether the specified process is relevant to this
#   handler (this may be determined using process name, command line, UID, parent relationships, or
#   any other available process data), determine whether any cgroups changes are needed, then make
#   any necessary changes.  In general, this callback should reclassify a process and all of its
#   threads at the same time, however it may handle a process and its threads differently if
#   necessary.  If necessary, this callback is responsible for creating and configuring cgroups
#   before assigning processes to them.  When practical, any created cgroups should be namespaced to
#   allow an associated "cleanup" callback to identify and remove only the relevant cgroups.  See
#   http://www.freedesktop.org/wiki/Software/systemd/PaxControlGroups/ for additional cgroups
#   rules/conventions.
#   Note that any new processes spawned by this callback will trigger additional calls to this
#   callback.  To avoid infinite loops, this callback must be careful to avoid spawning new
#   processes.
#   The "proc" argument is a psutil.Process object for the specified "pid".  See
#   http://pythonhosted.org/psutil/#process-class for documentation.  The "event_args" argument is
#   the arguments dict associated with the proc_events or reliable_proc_events event that triggered
#   this callback.
#   This callback should return True if the specified process is relevant to this handler, or False
#   if the specified process is not relevant.  If True is returned, no further callbacks will be
#   called for this process.  If False is returned, cgroupsd_listener will continue to iterate
#   through the registered "process" callbacks.  If no "process" callbacks return True for the
#   process, then cgroupsd_listener will iterate through the registered "thread" callbacks.
# handlers['thread'] -> callback(type='thread', tid, tproc, pid, proc, event_args)
#   This is called if a thread (that may or may not be a thread group leader) may need to be
#   reclassified into cgroups.
#   On start-up, this will be called repeatedly for each existing thread.  During normal operation,
#   this will be called any time a process or thread is spawned, changes its uid or gid, or changes
#   its "comm" value (its command name as output by `ps -o comm`).  If process events are lost or
#   cannot be received, this may be called periodically for each existing thread.
#   When iterating through existing processes/threads, if a "process" callback returns True, then
#   this will not be called for any threads in that process' thread group.  When handling process
#   events, "process" callbacks will only be called for thread group leaders, so this may be called
#   for threads that are not group leaders but whose thread group leader would cause a "process"
#   callback to return True.  However, if a "process" callback returns True for a thread group
#   leader, then this will not be called for that thread group leader.
#   When called, this callback should determine whether the specified thread is relevant to this
#   handler (this may be determined using thread name, command line, UID, thread group or process
#   parent relationships, or any other available process data), determine whether any cgroups
#   changes are needed, then make any necessary changes.  If necessary, this callback is responsible
#   for creating and configuring cgroups before assigning processes/threads to them.  When
#   practical, any created cgroups should be namespaced to allow an associated "cleanup" callback to
#   identify and remove only the relevant cgroups.  See
#   http://www.freedesktop.org/wiki/Software/systemd/PaxControlGroups/ for additional cgroups
#   rules/conventions.
#   Note that any new processes or threads spawned by this callback will trigger additional calls
#   to this callback.  To avoid infinite loops, this callback must be careful to avoid spawning new
#   processes or threads.
#   The "tid" argument is the PID of the thread, and the "pid" argument is the PID of the thread
#   group leader.  For threads that are thread group leaders, tid == pid.  The "tproc" and "proc"
#   arguments are psutil.Process objects for the specified "tid" and "pid" respectively.  See
#   http://pythonhosted.org/psutil/#process-class for documentation.  The "event_args" argument is
#   the arguments dict associated with the proc_events or reliable_proc_events event that triggered
#   this callback.
#   This callback should return True if the specified thread is relevant to this handler, or False
#   if the specified thread is not relevant.  If True is returned, no further callbacks will
#   be called for this thread.  If False is returned, cgroupsd_listener will continue to iterate
#   through the registered "thread" callbacks.
# handlers['cleanup'] -> callback(type='cleanup', tid, pid, event_args)
#   This is intended to be used to clean up empty cgroups.
#   It is called with tid=None and pid=None when cgroupsd_listener iterates through existing
#   processes/threads on start-up or if process events are lost or cannot be received.  (It is only
#   called once after each full iteration.)  It is also called with a tid/pid when a process event
#   is received indicating that a thread or process has exited.  The "event_args" argument is the
#   arguments dict associated with the proc_events or reliable_proc_events event that triggered
#   this callback.
#   Note that any short-lived processes or threads spawned by this callback will trigger additional
#   calls to this callback.  To avoid infinite loops, this callback must be careful to avoid
#   spawning short-lived processes or threads.
#   Callbacks may internally cache thread/process data to speed up cleanup when known processes or
#   threads exit.  However, callbacks should also be capable of scanning existing cgroups and
#   performing any necessary cleanup without knowing what processes (if any) have exited.   When
#   practical, "process" and "thread" callbacks should namespace any created cgroups to allow an
#   associated "cleanup" callback to identify and remove only the relevant cgroups.
#   This callback should always return False.
#



import logging  # Log levels: debug info warning error/exception critical
if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG)
__logger = logging.getLogger(__name__)

import proc_events
from reliable_proc_events import ReliableProcEvents
import psutil

# This ProcessHandlers class is loosely based on the examples here:
# http://stackoverflow.com/questions/1092531/event-system-in-python
class ProcessHandlers(list):
  def __init__(self, type, logger): self.type = type ; self.__logger = logger
  def __iadd__(self, handler): self.append(handler) ; return self
  def __isub__(self, handler): self.remove(handler) ; return self
  def __call__(self, *list_args, **keyword_args):
    self.__logger.debug('Calling process handlers of type {0} with args {1} {2}:'.format(self.type, list_args, keyword_args))
    keyword_args['type'] = self.type
    for f in self:
      try:
        if f(*list_args, **keyword_args):
          self.__logger.debug('Process handler {0} handled call with args {1} {2}'.format(f, list_args, keyword_args))
          return True
      except: self.__logger.exception('Exception thrown in process handler of type {0} with args {1} {2}:'.format(self.type, list_args, keyword_args))
    return False
# In Python 2.7, dict((a,'b') for a in c) can be shortened to {a:'b' for a in c}
handlers = dict( (type, ProcessHandlers(type, __logger)) for type in ['process', 'thread', 'cleanup'] )

__r = None

def start():
  global __r
  if __r: raise RuntimeError('cgroupsd_listener.start() has already been started')
  for event in ['fork', 'exec', 'uid', 'gid', 'comm']:
    proc_events.handlers[event] += __handle_proc_event
  proc_events.handlers['exit'] += __handle_exit_event
  __r = ReliableProcEvents(__iterate_all_procs)

def stop():
  global __r
  if not __r: return
  __r.stop()
  __r = None

def __iterate_all_procs(**event_args):
  __logger.debug('Iterating through all processes')
  for proc in psutil.process_iter():
    try:
      pid = proc.pid
      if not handlers['process'](pid=pid, proc=proc, event_args=event_args):
        for thread in proc.threads():
          tid = thread.id
          try: tproc = psutil.Process(tid)
          except (psutil.NoSuchProcess, psutil.AccessDenied): continue
          handlers['thread'](tid=tid, tproc=tproc, pid=pid, proc=proc, event_args=event_args)
    except psutil.NoSuchProcess: continue
  handlers['cleanup'](pid=None, tid=None, event_args=event_args)

def __handle_proc_event(**event_args):
  pid = event_args['pid']
  tid = event_args['tid']
  __logger.debug('Handling PID {0} TID {1}'.format(pid, tid))
  try: proc = psutil.Process(pid)
  except (psutil.NoSuchProcess, psutil.AccessDenied): return
  if pid == tid:
    if handlers['process'](pid=pid, proc=proc, event_args=event_args): return
  try: tproc = psutil.Process(tid)
  except (psutil.NoSuchProcess, psutil.AccessDenied): return
  handlers['thread'](tid=tid, tproc=tproc, pid=pid, proc=proc, event_args=event_args)

def __handle_exit_event(**event_args):
  pid = event_args['pid']
  tid = event_args['tid']
  __logger.debug('Handling exit of PID {0} TID {1}'.format(pid, tid))
  handlers['cleanup'](pid=pid, tid=tid, event_args=event_args)

if __name__ == '__main__':
  start()

  # Run until signal (CTRL-C)
  import signal
  try: signal.pause()
  # CTRL-C causes ^C to be printed without a trailing newline
  except KeyboardInterrupt: sys.stderr.write('\n')

  stop()
