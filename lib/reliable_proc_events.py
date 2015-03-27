#!/usr/bin/env python

#
# Copyright 2015 Paul Donohue <python_reliable_proc_events@PaulSD.com>
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
# Reliable Linux Process Events Module
#
# This class listens for "events_failed", "events_good", and "events_lost" events from the
# proc_events module and will periodically call a configured handler function when events have been
# lost or are unavailable.  The handler function can iterate through all running processes to ensure
# that process changes are captured even when events are unreliable.
#
# If events are available at instantiation, the configured handler function will be called once
# shortly after instantiation.  If events are unavailable at instantiation, the handler function
# will be called either when events become available or after the configured delay.
#
# To avoid endless churning under heavy load (if the configured handler function is taking a long
# time to run, or if we are receiving lots of events_lost events), this class sleeps for a
# configured delay after each call to the handler function.  If the handler function must be called
# on a particular interval regardless of the execution time of the handler function itself, then
# move the last_sync_time assignment above the call to the handler in __sync_loop(), and adjust the
# failed_wake_lock.wait() call to use self.delay for the first loop after events fail and
# (self.delay - (utcnow() - last_sync_time)) for subsequent loops.
#
# See the comments in proc_events.py for prerequisites.
#
# Basic Usage:
# import proc_events
# from reliable_proc_events import ReliableProcEvents
# # For reliable operation, normal event handlers should be registered before instantiating
# # ReliableProcEvents()
# proc_events.handlers['exec'] += my_exec_handler
# def sync_needed_handler(event='sync_needed'):
#   do_iterate_procs()
# r = ReliableProcEvents(sync_needed_handler)
# ...
# r.stop()  # Optional
#



import logging  # Log levels: debug info warning error/exception critical
if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG)

import proc_events
import threading
from datetime import datetime

class ReliableProcEvents(object):

  def __init__(self, handler, delay=60):  # delay in seconds
    self.handler = handler
    self.delay = delay
    self.__logger = logging.getLogger(__name__)

    proc_events.handlers['events_failed'] += self.__handle_event
    proc_events.handlers['events_good'] += self.__handle_event
    proc_events.handlers['events_lost'] += self.__handle_event

    self.stopping = False
    self.sync_needed = True
    self.failed_wake_lock = threading.Event()
    self.good_wake_lock = threading.Event()
    self.lost_wake_lock = threading.Event()
    self.thread = threading.Thread(target=self.__sync_loop)
    self.thread.daemon = True
    self.thread.start()

  def stop(self):
    if not self.thread.is_alive(): return
    self.__logger.debug('Stopping sync loop')
    self.stopping = True
    self.failed_wake_lock.set()
    self.good_wake_lock.set()
    self.lost_wake_lock.set()
    self.thread.join()

  def __handle_event(self, event, **data):
    self.__logger.debug('Received {0} event'.format(event))
    self.sync_needed = True
    if event == 'events_good': self.failed_wake_lock.set()
    else: self.good_wake_lock.set()

  def __sync_loop(self):
    self.__logger.debug('Starting sync loop')
    last_sync_time = datetime.min
    while not self.stopping:
      if not proc_events.events_good:
        self.sync_needed = True
        self.__logger.debug('Events unavailable.  Sleeping sync loop for {0} seconds or until events_good or stop()'.format(self.delay))
        self.failed_wake_lock.wait(self.delay) ; self.failed_wake_lock.clear()
        if self.stopping: break
      if self.sync_needed:
        delta = datetime.utcnow() - last_sync_time
        if delta.days == 0 and delta.seconds < self.delay:
          self.__logger.debug('Throttling sync_needed call.  Sleeping sync loop for {0} seconds or until stop()'.format(self.delay - delta.seconds))
          self.lost_wake_lock.wait(self.delay - delta.seconds) ; self.lost_wake_lock.clear()
          if self.stopping: break
        self.sync_needed = False
        self.__logger.debug('Firing sync_needed event')
        try: self.handler(event='sync_needed')
        except: self.__logger.exception('Exception thrown in handler:')
        last_sync_time = datetime.utcnow()
      else:
        self.__logger.debug('Events good.  Sleeping sync loop until events_failed, events_lost, or stop()')
        self.good_wake_lock.wait() ; self.good_wake_lock.clear()
    self.__logger.debug('Stopped sync loop')

if __name__ == '__main__':
  for event in proc_events.handlers.iterkeys(): proc_events.handlers[event] += proc_events.log_event

  r = ReliableProcEvents(proc_events.log_event)

  # Run until signal (CTRL-C)
  import signal
  import sys
  try: signal.pause()
  # CTRL-C causes ^C to be printed without a trailing newline
  except KeyboardInterrupt: sys.stderr.write('\n')

  r.stop()
