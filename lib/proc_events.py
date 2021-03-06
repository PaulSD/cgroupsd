#!/usr/bin/env python

#
# Copyright 2015 Paul Donohue <python_proc_events@PaulSD.com>
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
# Linux Process Events Module
#
# This module listens to the Linux Kernel's Process Events Connector and calls configured event
# handler functions as events are generated.
#
# Users of this module must be careful to filter events generated by threads or processes spawned
# by this process to avoid infinite loops.  When possible, it is best to simply avoid implementing
# any behavior in an event handler that might spawn a thread or process or otherwise generate an
# event.
#
# See the comments in libnl.py for prerequisites.
#
# Basic Usage:
# import proc_events
# def exec_handler(event, pid, tid):
#   print('PID {0} started'.format(pid))
# proc_events.handlers['exec'] += exec_handler
# def any_handler(event, **data):
#   print('Got {0} event'.format(event))
# for event in proc_events.handlers.iterkeys(): proc_events.handlers[event] += any_handler
#
# Supported Events:
# handlers['fork'] -> callback(event='fork', pid, tid, parent_pid, parent_tid)
#   Process has been created via fork()
# handlers['exec'] -> callback(event='exec', pid, tid)
#   Process has been replaced via exec()
# handlers['uid'] -> callback(event='uid', pid, tid, real_uid, effective_uid)
#   Process UID changed (Arguments are the new real/effective UID)
# handlers['gid'] -> callback(event='gid', pid, tid, real_gid, effective_gid)
#   Process GID changed (Arguments are the new real/effective GID)
# handlers['sid'] -> callback(event='sid', pid, tid)
#   Process has become a session leader (See http://lwn.net/Articles/337708/ )
# handlers['ptrace'] -> callback(event='ptrace', pid, tid, tracer_pid, tracer_tid)
#   ptrace() has attached to process
# handlers['comm'] -> callback(event='comm', pid, tid, command)
#   Process command name has changed (See https://lkml.org/lkml/2011/8/2/276 )
# handlers['coredump'] -> callback(event='coredump', pid, tid)
#   Process has dumped a core file
# handlers['exit'] -> callback(event='exit', pid, tid, exit_status, exit_signal)
#   Process has exited
# handlers['events_failed'] -> callback(event='events_failed')
#   The ability to receive events has been lost
# handlers['events_good'] -> callback(event='events_good')
#   The ability to receive events has been established or restored (Events may have been lost)
# handlers['events_lost'] -> callback(event='events_lost')
#   The kernel reported that one or more events have been lost
#



import os
if os.geteuid() != 0:
  # Non-root users can connect to NETLINK_CONNECTOR, but only root users can subscribe to the
  # CN_IDX_PROC multicast group.
  raise RuntimeError('The proc_events module requires this program to be run as root')

import logging  # Log levels: debug info warning error/exception critical
if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG)
__logger = logging.getLogger(__name__)



from libnl import libnl, libnl_ffi, libnl_check
import select
import errno

# If you get buffer overruns (-NLE_NOMEM errors from nl_recvmsgs()), you may want to increase this
pe_nl_rx_buffer_size = 32768  # bytes

# This is updated whenever the ability to receive events is lost or restored, and may be used to
# handle the case where the ability to receive events was never established or was lost before an
# "events_failed" handler was registered.
events_good = False

# This EventHandlers class is loosely based on the examples here:
# http://stackoverflow.com/questions/1092531/event-system-in-python
class EventHandlers(list):
  def __init__(self, event, logger): self.event = event ; self.__logger = logger
  def __iadd__(self, handler): self.append(handler) ; return self
  def __isub__(self, handler): self.remove(handler) ; return self
  def __call__(self, *list_args, **keyword_args):
    self.__logger.debug('{0} event handler called with args {1} {2}:'.format(self.event, list_args, keyword_args))
    keyword_args['event'] = self.event
    for f in self:
      try: f(*list_args, **keyword_args)
      except: self.__logger.exception('Exception thrown in {0} event handler with args {1} {2}:'.format(self.event, list_args, keyword_args))
# In Python 2.7, dict((a,'b') for a in c) can be shortened to {a:'b' for a in c}
handlers = dict( (event, EventHandlers(event, __logger)) for event in
  ['fork', 'exec', 'uid', 'gid', 'sid', 'ptrace', 'comm', 'coredump', 'exit',
   'events_failed', 'events_good', 'events_lost'] )

# Simple event handler that logs events
def log_event(**args):
  full_args = []
  for k, v in args.iteritems():
    full_args.append('{0}: {1}'.format(k, v))
  __logger.info(', '.join(full_args))
if __name__ == '__main__':
  for event in handlers.iterkeys(): handlers[event] += log_event

@libnl_ffi.callback('nl_recvmsg_msg_cb_t')
def __msg_cb(msg, arg):
  # Extract the netlink message (Already validated by libnl)
  nl_msg_hdr = libnl.nlmsg_hdr(msg)
  # Validate the netlink message's payload length
  if nl_msg_hdr.nlmsg_len < libnl.nlmsg_size(libnl_ffi.sizeof('struct cn_msg')):
    __logger.warn('Received a short NETLINK_CONNECTOR message, will ignore and continue (Expected {0} bytes but got {1} bytes)'.format(libnl.nlmsg_size(libnl_ffi.sizeof('struct cn_msg')), nl_msg_hdr.nlmsg_len))
    return libnl.NL_SKIP
  # Extract and validate the NETLINK_CONNECTOR message
  # cn_msg.seq should match nl_msg_hdr.nlmsg_seq, but we don't really need to validate it
  # cn_msg.flags is not used by the PROC CONNECTOR
  cn_msg = libnl_ffi.cast('struct cn_msg *', libnl.nlmsg_data(nl_msg_hdr))
  if cn_msg.id.idx != libnl.CN_IDX_PROC or cn_msg.id.val != libnl.CN_VAL_PROC:
    __logger.warn('Received a NETLINK_CONNECTOR message with an unexpected ID, will ignore and continue (Expected idx:{0} val:{1} but got idx:{2} val:{3}) (See /usr/include/linux/connector.h)'.format(cn_msg.id.idx, cn_msg.id.val, libnl.CN_IDX_PROC, libnl.CN_VAL_PROC))
    return libnl.NL_SKIP
  # Validate the NETLINK_CONNECTOR message's payload length
  if cn_msg.len < libnl_ffi.sizeof('struct proc_event'):
    __logger.warn('Received a short PROC CONNECTOR event, will ignore and continue (Expected {0} bytes but got {1} bytes)'.format(libnl_ffi.sizeof('struct proc_event'), cn_msg.len))
    return libnl.NL_SKIP
  if nl_msg_hdr.nlmsg_len < libnl.nlmsg_size(libnl_ffi.sizeof('struct cn_proc_reply')):
    __logger.warn('Received a NETLINK message with valid payload length but invalid message length, will ignore and continue (Expected {0} bytes but got {1} bytes)'.format(libnl.nlmsg_size(libnl_ffi.sizeof('struct cn_proc_reply')), nl_msg_hdr.nlmsg_len))
    return libnl.NL_SKIP
  # Extract and validate the PROC CONNECTOR event
  event = libnl_ffi.cast('struct cn_proc_reply *', libnl.nlmsg_data(nl_msg_hdr)).event
  if (cn_msg.ack != 0 and event.what != libnl.PROC_EVENT_NONE) or \
     (cn_msg.ack == 0 and event.what == libnl.PROC_EVENT_NONE):
    __logger.warn("Received a PROC CONNECTOR event with an unexpected combination of 'ack' and 'what' values, will ignore and continue (ack: {0} what: {1})".format(cn_msg.ack, event.what))
    return libnl.NL_SKIP
  ev_type = event.what
  ev_data = event.event_data

  # If the ability to receive events has not been established or was lost, it looks like things are
  # working now.
  global events_good
  if not events_good:
    events_good = True
    handlers['events_good']()

  # Parse the PROC CONNECTOR event (See /usr/include/linux/cn_proc.h)
  if ev_type == libnl.PROC_EVENT_NONE:
    # ACK in response to PROC_CN_MCAST_LISTEN or PROC_CN_MCAST_IGNORE message, don't fire an event
    if ev_data.ack.err != 0: __logger.warn('Received a PROC CONNECTOR ACK message with error code {0}'.format(ev_data.ack.err))
    else: __logger.debug('Received a PROC CONNECTOR ACK message')
  elif ev_type == libnl.PROC_EVENT_FORK:
    # Process has been created via fork()
    handlers['fork'](
      pid = ev_data.fork.child_tgid,
      tid = ev_data.fork.child_pid,
      parent_pid = ev_data.fork.parent_tgid,
      parent_tid = ev_data.fork.parent_pid,
      )
  elif ev_type == libnl.PROC_EVENT_EXEC:
    # Process has been replaced via exec()
    handlers['exec'](
      # 'exec' is a python keyword, so we have to use getattr(ev_data,'exec') instead of
      # ev_data.exec
      pid = getattr(ev_data,'exec').process_tgid,
      tid = getattr(ev_data,'exec').process_pid,
      )
  elif ev_type == libnl.PROC_EVENT_UID:
    # Process UID changed
    handlers['uid'](
      pid = ev_data.id.process_tgid,
      tid = ev_data.id.process_pid,
      real_uid = ev_data.id.r.ruid,
      effective_uid = ev_data.id.e.euid,
      )
  elif ev_type == libnl.PROC_EVENT_GID:
    # Process GID changed
    handlers['gid'](
      pid = ev_data.id.process_tgid,
      tid = ev_data.id.process_pid,
      real_gid = ev_data.id.r.rgid,
      effective_gid = ev_data.id.e.egid,
      )
  elif ev_type == libnl.PROC_EVENT_SID:
    # Process has become a session leader
    # See http://lwn.net/Articles/337708/
    handlers['sid'](
      pid = ev_data.sid.process_tgid,
      tid = ev_data.sid.process_pid,
      )
  elif hasattr(libnl, 'PROC_EVENT_PTRACE') and ev_type == libnl.PROC_EVENT_PTRACE:
    # ptrace() has attached to process
    handlers['ptrace'](
      pid = ev_data.ptrace.process_tgid,
      tid = ev_data.ptrace.process_pid,
      tracer_pid = ev_data.ptrace.tracer_tgid,
      tracer_tid = ev_data.ptrace.tracer_pid,
      )
  elif hasattr(libnl, 'PROC_EVENT_COMM') and ev_type == libnl.PROC_EVENT_COMM:
    # Process command name has changed
    # See https://lkml.org/lkml/2011/8/2/276
    handlers['comm'](
      pid = ev_data.comm.process_tgid,
      tid = ev_data.comm.process_pid,
      command = libnl_ffi.string(ev_data.comm.comm),
      )
  elif hasattr(libnl, 'PROC_EVENT_COREDUMP') and ev_type == libnl.PROC_EVENT_COREDUMP:
    # Process has dumped a core file
    handlers['coredump'](
      pid = ev_data.coredump.process_tgid,
      tid = ev_data.coredump.process_pid,
      )
  elif ev_type == libnl.PROC_EVENT_EXIT:
    # Process has exited
    handlers['exit'](
      pid = ev_data.exit.process_tgid,
      tid = ev_data.exit.process_pid,
      exit_status = ev_data.exit.exit_code,
      exit_signal = ev_data.exit.exit_signal,
      )
  else:
    __logger.debug("Received a PROC CONNECTOR event with an unknown 'what' value, will ignore and continue ({0}) (See /usr/include/linux/cn_proc.h)".format(event.what))
    return libnl.NL_SKIP

  return libnl.NL_OK

@libnl_ffi.callback('nl_recvmsg_err_cb_t')
def __err_cb(nl_addr, nl_err, arg):
  err_num = nl_err.error
  try: err_str = os.strerror(err_num)
  except: err_str = '(Unknown error)'
  __logger.warn('Received NLMSG_ERROR with error code {0}: {1}  (Will ignore and continue)'.format(err_num, err_str))
  # See the notes in libnl.py about the error message callback
  return lbinl.NL_SKIP

__exit = False
__thread_id = -1

def __listen():
  __logger.debug('Connecting to the netlink proc connector')
  nl_sock = libnl.nl_socket_alloc()
  if nl_sock == libnl_ffi.NULL: raise RuntimeError('Error allocating nl_sock')
  try:
    # Register callbacks
    libnl_check(libnl.nl_socket_modify_cb(nl_sock, libnl.NL_CB_FINISH, libnl.NL_CB_CUSTOM, __msg_cb, libnl_ffi.NULL))
    libnl_check(libnl.nl_socket_modify_err_cb(nl_sock, libnl.NL_CB_CUSTOM, __err_cb, libnl_ffi.NULL))
    # Multicast event sequence numbers are not sequential, so do not attempt to verify them
    libnl.nl_socket_disable_seq_check(nl_sock)
    # Connect
    libnl_check(libnl.nl_connect(nl_sock, libnl.NETLINK_CONNECTOR))
    try:
      # Subscribe to the PROC CONNECTOR's multicast group
      libnl_check(libnl.nl_socket_add_membership(nl_sock, libnl.CN_IDX_PROC))
      # Only need to send two messages, so tx buffer can be small
      libnl_check(libnl.nl_socket_set_buffer_size(nl_sock, pe_nl_rx_buffer_size, 128))
      # Increment the PROC CONNECTOR's internal listener counter to ensure that it sends messages.
      # This must be sent after we subscribe to the multicast group so that we can use the ACK to
      # trigger the "events_good" event.  (See the notes in libnl.py about the PROC CONNECTOR's
      # internal counter.)
      cn_proc_msg = libnl_ffi.new('struct cn_proc_msg *')  # libnl_ffi.new() calls memset(0) for us
      cn_proc_msg.cn_msg.id.idx = libnl.CN_IDX_PROC;
      cn_proc_msg.cn_msg.id.val = libnl.CN_VAL_PROC;
      cn_proc_msg.cn_msg.len = libnl_ffi.sizeof('enum proc_cn_mcast_op')
      cn_proc_msg.cn_mcast = libnl.PROC_CN_MCAST_LISTEN
      cn_proc_msg_size = libnl_ffi.sizeof('struct cn_proc_msg')
      libnl_check(libnl.nl_send_simple(nl_sock, libnl.NLMSG_DONE, 0, cn_proc_msg, cn_proc_msg_size))
      try:
        # Use non-blocking mode so we can wake select() with a signal or a timeout
        # In blocking mode, nl_recv() loops on signals, and we have no way to stop that loop
        libnl_check(libnl.nl_socket_set_nonblocking(nl_sock))
        nl_sock_fd = libnl.nl_socket_get_fd(nl_sock)
        # We can only wake select() with a signal if we know the ID of this thread
        # Otherwise we have to periodically wake select() with a timeout to determine when to exit
        if __thread_id < 0:
          __logger.info('Thread ID not available, will periodically wake select() to determine when to exit')
          select_timeout = 3
        else: select_timeout = None
        __logger.debug('Connected to the netlink proc connector')
        while not __exit:
          try: r, w, x = select.select([nl_sock_fd], [], [nl_sock_fd], select_timeout)
          except select.error as e:
            err_num, err_str = e.args
            if err_num == errno.EINTR: continue  # Woken by a signal
            raise RuntimeError('select() returned error: {0}'.format(e))
          if len(r) == 0 and len(x) == 0: continue  # Timeout
          err_num = libnl.nl_recvmsgs_default(nl_sock)
          if err_num == -libnl.NLE_AGAIN: continue
          if err_num == -libnl.NLE_NOMEM:  # See the notes in libnl.py about NLMSG_OVERRUN
            handlers['events_lost']()
            continue
          libnl_check(err_num)  # Throw an exception on other errors
      finally:
        __logger.debug('Disconnecting from the netlink proc connector')
        global events_good
        events_good = False
        if not __exit: handlers['events_failed']()
        # If we're here because nl_recvmsgs() or select() failed then this probably won't work, but
        # we will try it anyway and ignore any errors.  Since the socket is in non-blocking mode,
        # you might think we need to check for NLE_AGAIN, however the 128 byte TX buffer configured
        # above should be large enough to hold both of the messages we send, so NLE_AGAIN should
        # never happen.
        cn_proc_msg.cn_mcast = libnl.PROC_CN_MCAST_IGNORE
        libnl.nl_send_simple(nl_sock, libnl.NLMSG_DONE, 0, cn_proc_msg, cn_proc_msg_size)
    finally: libnl.nl_close(nl_sock)
  finally: libnl.nl_socket_free(nl_sock)



import threading
from datetime import datetime
import signal
import sys

pe_throttle_interval = 3  # seconds
__listen_wake_lock = threading.Event()

# Python doesn't provide any mechanism for obtaining the OS thread ID, which we need to send a
# signal to interrupt select() on exit.  Attempt to obtain it using a gettid system call via ctypes.
def __get_thread_id():
  try:
    # Unfortunately there is no glibc symbol for gettid(), and there is no good way to look up the
    # syscall number for it, so we have to hard-code it.
    gettid = -1
    import platform
    # Linux can probably be assumed for this particular module, but just in case
    if platform.system() == 'Linux':
      # This logic comes from /usr/include/asm/unistd.h in Linux 3.16.0
      if platform.machine() == 'i386':
        gettid = 224  # Defined in asm/unistd_32.h
      elif platform.machine() == 'x86_64':
        if sys.maxint == 2**31-1:  # Max signed integer
          x32_syscall_bit = 0x40000000  # Defined in asm/unistd.h
          gettid = x32_syscall_bit + 186  # Defined in asm/unistd_x32.h
        elif sys.maxint == 2**63-1:  # Max signed integer
          gettid = 186  # Defined in asm/unistd_64.h
    if gettid > 0:
      import ctypes
      global __thread_id
      __thread_id = ctypes.CDLL('libc.so.6').syscall(gettid)
  except:
    # If an error occurs, we will simply fall back to periodically waking select()
    pass

def __listen_loop():
  __logger.debug('Starting listen loop')
  __get_thread_id()
  last_exception_time = datetime.min
  while not __exit:
    try:
      __listen()
    except:
      __logger.exception('Exception thrown in listen loop, will restart:')
      delta = datetime.utcnow() - last_exception_time
      if delta.days == 0 and delta.seconds < pe_throttle_interval:
        __logger.info('Throttling listen loop for {0} seconds'.format(pe_throttle_interval))
        __listen_wake_lock.wait(pe_throttle_interval)
      last_exception_time = datetime.utcnow()
  __logger.debug('Stopped listen loop')

__thread = threading.Thread(target=__listen_loop)
__thread.daemon = True

def __stop():
  if not __thread.is_alive(): return
  __logger.debug('Stopping listen loop')
  global __exit
  __exit = True
  if __thread_id > 0:
    try: os.kill(__thread_id, signal.SIGINT)  # Wake select() in __listen()
    except KeyboardInterrupt: pass
  # os.kill() should trigger a KeyboardInterrupt immediately, but that sometimes doesn't happen
  # until the __thread.join() call, so we must catch it on every call from here on out.
  try: __listen_wake_lock.set()  # Wake __listen_wake_lock.wait() in __listen_loop()
  except KeyboardInterrupt: __listen_wake_lock.set()
  try: __thread.join()
  except KeyboardInterrupt: __thread.join()

# Stop the listen loop when Python exits
import atexit
atexit.register(__stop)

# Start the listen loop when this file is imported
# (Run last to avoid starting if any exceptions are thrown above)
__thread.start()

if __name__ == '__main__':
  # Run until signal (CTRL-C)
  try: signal.pause()
  # CTRL-C causes ^C to be printed without a trailing newline
  except KeyboardInterrupt: sys.stderr.write('\n')
