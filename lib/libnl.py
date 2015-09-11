#!/usr/bin/env python

#
# Copyright 2015 Paul Donohue <python_libnl@PaulSD.com>
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# license used by libnl, which is currently version 2.1 of the GNU Lesser General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along with this program.
# If not, see <http://www.gnu.org/licenses/>.
#

#
# cffi-based Python bindings for libnl
#
# Prerequisites:
# libnl : `sudo apt-get install libnl-3-200` or `sudo yum install libnl3`
# libnl headers : `sudo apt-get install libnl-3-dev` or `sudo yum install libnl3-devel`
# cffi : `sudo apt-get install python-cffi` or
#        `sudo yum install python-pip python-devel libffi-devel ; sudo pip install cffi`
# (cffi v0.8.2 or later is required for #define and packed=True support in cdef())
#
# Basic Usage (equivalent to http://www.infradead.org/~tgr/libnl/doc/core.html#_multicast_example):
# from libnl import libnl, libnl_ffi, libnl_check
# @libnl_ffi.callback('nl_recvmsg_msg_cb_t')
# def my_func(msg, arg):
#   # If this is a class method:
#   self = libnl_ffi.from_handle(arg)
#   return libnl.NL_OK
# socket = libnl.nl_socket_alloc()
# libnl.nl_socket_disable_seq_check(socket)
# # If the callback is a class method, use libnl_ffi.new_handle(self) instead of libnl_ffi.NULL:
# libnl.nl_socket_modify_cb(socket, libnl.NL_CB_VALID, libnl.NL_CB_CUSTOM, my_func, libnl_ffi.NULL)
# libnl.nl_connect(socket, libnl.NETLINK_ROUTE)
# libnl.nl_socket_add_membership(socket, libnl.RTNLGRP_LINK)
# while True:
#   libnl.nl_recvmsgs_default(socket)
#

# Relevant Documentation:
# libnl: http://www.infradead.org/~tgr/libnl/doc/core.html
# AF_NETLINK: http://man7.org/linux/man-pages/man7/netlink.7.html
#   https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/net/netlink/af_netlink.c
# NETLINK_CONNECTOR: https://www.kernel.org/doc/Documentation/connector/connector.txt
# PROC CONNECTOR: https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/include/uapi>
#   https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/drivers/connector/cn_proc.c
#   http://lwn.net/Articles/157150/
# cffi: https://cffi.readthedocs.org/en/latest/

# Some netlink notes:
# * In most cases, subscribing to a netlink multicast group requires root or CAP_NET_ADMIN.
# * For each message, libnl will call any NL_CB_MSG_IN, NL_CB_SQ_CHECK, and NL_CB_SEND_ACK callbacks
#   followed by only one of NL_CB_FINISH, NL_CB_SKIPPED, NL_CB_OVERRUN, NL_CB_ACK, NL_CB_INVALID,
#   NL_CB_VALID, or the "error message callback" (registered via nl_socket_modify_err_cb())
#   depending on the message type: NL_CB_FINISH for NLMSG_DONE, NL_CB_SKIPPED for NLMSG_NOOP,
#   NL_CB_OVERRUN for NLMSG_OVERRUN, NL_CB_ACK for NLMSG_ERROR with error code 0, the "error message
#   callback" for NLMSG_ERROR with a non-zero error code, NL_CB_INVALID for a truncated NLMSG_ERROR
#   or a message with a bad sequence number, or NL_CB_VALID for any other message type including
#   NLM_F_MULTI.  The documentation for NL_CB_VALID says it is called for "each valid message", but
#   it is actually only called for messages that do not match one of the other callback message
#   types.
# * On http://www.infradead.org/~tgr/libnl/doc/core.html#_callback_hooks, the "Default Return Value"
#   listed for NL_CB_FINISH and NL_CB_ACK are incorrect.  The default for each is listed as NL_STOP,
#   but the default return value if no callback was registered is actually NL_OK.
# * If no "error message callback" is registered, or if the callback returns NL_STOP, then
#   nl_recvmsgs() will return an error based on the error code in the message for NLMSG_ERROR
#   messages.  It is safe to return NL_SKIP or NL_OK from the callback to continue using the socket
#   without reconnecting.  However, due to the way the error codes are mapped, it is probably not
#   safe to ignore these errors from nl_recvmsgs().  (There is no good way to determine whether a
#   nl_recvmsgs() error came from an NLMSMG_ERROR or some other part of libnl, so you should always
#   assume it is unsafe and reconnect before continuing.)
# * NLMSG_OVERRUN is a vestigial remnant of the original netlink character device and is not used by
#   AF_NETLINK.  Therefore libnl will never call any NL_CB_OVERRUN callbacks.  AF_NETLINK instead
#   returns -ENOBUFS on the next read after an overrun or otherwise lost packet.  If that happens,
#   nl_recv() or nl_recvmsgs() in libnl will return -NLE_NOMEM.  libnl will also return -NLE_NOMEM
#   for actual out-of-memory errors, however it appears to be safe to continue using the socket
#   without reconnecting after either buffer overruns or libnl out-of-memory errors.
# * If no NL_CB_INVALID callback is registered, then nl_recvmsgs() will return -NLE_MSG_TRUNC or
#   -NLE_SEQ_MISMATCH.  It is probably not a good idea to continue using the socket after these
#   errors, so you should reconnect before continuing.
# * NETLINK_CONNECTOR and the PROC CONNECTOR do not follow many of the netlink conventions described
#   in the libnl docs.  For example: nlmsghdr.nlmsg_flags is ignored, cn_msg.seq duplicates
#   nlmsghdr.nlmsg_seq, and custom data structures are used instead of nlattr.  This may be because
#   NETLINK_CONNECTOR predates AF_NETLINK and the current conventions?
# * The PROC CONNECTOR has an internal counter that it uses to avoid sending messages if there are
#   no listeners.  To increment/decrement this counter, listeners are required to send messages when
#   they start/stop listening.  A multicast ACK reply is sent to all listeners when this message is
#   received (the original sender will not see the message if they are not subscribed to the
#   multicast group).  This seems rather bizarre and fragile.  For example, the counter will get out
#   of sync if a listener crashes and fails to send the "stop" message.  I'm not sure why it doesn't
#   just use netlink_has_listeners() to determine if there are any listeners:
#   http://lxr.free-electrons.com/source/net/netlink/af_netlink.c#L1866

# Some cffi notes:
# * To access a struct member whose name is a Python keyword (such as proc_event->exec), use
#   getattr(proc_event, 'exec')



# There are a number of options for interfacing with netlink:
# * Use the Python "socket" library and struct.pack()/unpack() as a low-level interface:
#   http://repo.or.cz/w/iotop.git/blob/HEAD:/iotop/netlink.py
#   http://git.sipsolutions.net/?p=pynl80211.git;a=blob;f=netlink.py
#   This would work here, but it isn't very readable or maintainable compared to the other options.
# * Use the "official" libnl Python bindings: https://github.com/thom311/libnl/tree/master/python
#   This is not readily available on Ubuntu or RHEL and is a pain to compile.
# * As of 2012, the libnl maintainer's plan was to replace the current Python bindings with new ones
#   based on ctypes: https://github.com/socketpair/python-libnl3-ctypes
#   This still (as of 2015) appears incomplete and does not support multicast (events).
# * Directly access libnl via ctypes.
#   This requires translating function prototypes, structs, and constants from C into Python.
#   Example using Ruby's ffi, which is somewhat similar to Python ctypes:
#   https://github.com/cultureulterior/ruby-netlink-libnl3/blob/master/libnl3.rb
# * Directly access libnl via cffi.
#   Function prototypes, structs, and constants can simply be copied and pasted from C header files.
# The last option seems like the best one, so that is what is implemented here.

from cffi import FFI
libnl_ffi = FFI()
libnl = libnl_ffi.dlopen('libnl-3.so.200')

import logging
__logger = logging.getLogger(__name__)

import re
import sys

# Some typedefs required by the header files below.
libnl_ffi.cdef('''
  typedef int8_t __s8;
  typedef int16_t __s16;
  typedef int32_t __s32;
  typedef int64_t __s64;
  typedef uint8_t __u8;
  typedef uint16_t __u16;
  typedef uint32_t __u32;
  typedef uint64_t __u64;

  typedef uint16_t __be16;

  typedef uint32_t socklen_t;
  typedef unsigned short __kernel_sa_family_t;  // From linux/socket.h

  typedef int pid_t;
  typedef int __kernel_pid_t;  // From asm-generic/posix_types.h
''')

# Under the hood, cffi uses https://github.com/eliben/pycparser which does not support preprocessor
# directives.  cffi adds a very basic #define parser which only supports values that are literal
# decimal or hex integers.  Therefore, cffi typically requires header file contents to be manually
# preprocessed then copied and pasted into an ffi.cdef() call.  (See
# https://groups.google.com/forum/#!msg/python-cffi/vDAw37NHRSg/L6vPpHR_3WkJ )
#
# However, libnl's use of preprocessor directives is minimal, so we can simply strip the unsupported
# directives and import the header files directly.  This will hopefully simplify maintenance and
# improve compatibility across versions of libnl.
__header_files = [
  # Included from libnl3/netlink/netlink.h
  'libnl3/netlink/netlink-compat.h',
  'linux/netlink.h',
  'linux/rtnetlink.h',
  'linux/genetlink.h',
  'linux/netfilter/nfnetlink.h',
  'libnl3/netlink/version.h',
  'libnl3/netlink/errno.h',
  'libnl3/netlink/handlers.h',
  'libnl3/netlink/socket.h',
  'libnl3/netlink/list.h',
  'libnl3/netlink/utils.h',
  'libnl3/netlink/object.h',
  'libnl3/netlink/netlink.h',
  # Included from libnl3/netlink/cache.h
  'libnl3/netlink/addr.h',
  'libnl3/netlink/data.h',
  'libnl3/netlink/attr.h',
  'libnl3/netlink/msg.h',
  'libnl3/netlink/cache.h',
  # Included from libnl3/netlink/route/link.h
  'libnl3/netlink/route/link.h',
  # NETLINK_CONNECTOR headers
  'linux/connector.h',
  'linux/cn_proc.h',
  ]
def __read_ffi_headers():
  # Python 2.6 does not support passing flags to re.sub(), so we must compile these
  ifdef_regex = re.compile(r'#ifdef.*?#endif', flags=re.DOTALL)
  cpp_regex = re.compile(r'^\s*#(?!define[ \t]+\S+[ \t]+[x0-9A-F]+\s*(/\*.*)?$)(.*\\\n)*.*$', flags=re.MULTILINE)
  attr_regex = re.compile(r'__attribute__\(\(.*\)\)', flags=re.MULTILINE)
  inline_regex = re.compile(r'\s+inline(\s+.*?)\{.*?\}', flags=re.DOTALL)
  for file in __header_files:
    file = '/usr/include/'+file
    data = open(file).read()
    # Strip any code between #ifdef and #endif statements.  This is an ugly hack, and there are lots
    # of ways this can go wrong, but it seems sufficient for the current libnl header files.
    data = ifdef_regex.sub('', data)
    # Strip any other preprocessor directives, except for #define with a literal integer value
    data = cpp_regex.sub('', data)
    # Strip __attribute__ tags, which are also unsupported
    data = attr_regex.sub('', data)
    # Strip inline function definitions, which are also unsupported
    data = inline_regex.sub(r'\1;', data)
    try:
      # 'packed=True' is required for proper alignment of struct fields used for packet encoding /
      # decoding
      libnl_ffi.cdef(data, packed=True)
    except:
      __logger.critical("Error parsing '{0}': {1}".format(file, sys.exc_info()[1]))
      sys.exit(1)
__read_ffi_headers()



# Additional data structures to simplify PROC CONNECTOR usage
libnl_ffi.cdef('''
  struct cn_proc_msg   { struct cn_msg cn_msg; enum proc_cn_mcast_op cn_mcast; };
  struct cn_proc_reply { struct cn_msg cn_msg; struct proc_event event; };
''', packed=True)

# Convenience function for checking the return values of libnl calls
def libnl_check(err_num):
  if err_num < 0:
    err_str = libnl_ffi.string(libnl.nl_geterror(err_num))
    raise RuntimeError('libnl returned error code {0}: {1}'.format(err_num, err_str))
