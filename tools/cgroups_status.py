#!/usr/bin/env python

#
# Copyright 2015 Paul Donohue <cgroups_status@PaulSD.com>
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
# Simple cgroups status checking tool.
#
# Some additional tools that may be useful can be found at
# https://github.com/peo3/cgroup-utils
#
# Prerequisites:
# cgroupspy : `sudo apt-get install python-pip ; sudo pip install cgroupspy` or
#             `sudo yum install python-pip ; sudo pip install cgroupspy`
# psutil (v2 or later) : `sudo apt-get install python-psutil` or
#                        `sudo yum install python-pip ; sudo pip install psutil`
#

from cgroupspy import trees
import psutil
import platform
import os

# /sys/fs/cgroup doesn't seem to be available in RHEL6, so use /cgroup/ instead
cgroups_root_path = '/sys/fs/cgroup/'
if 'Red Hat' in platform.linux_distribution()[0] and platform.linux_distribution()[1].startswith('6'):
  cgroups_root_path = '/cgroup/'

def print_all_cgroups(subsystems=[], sub_groups=[]):
  tree = trees.Tree(root_path=cgroups_root_path, groups=subsystems, sub_groups=sub_groups)
  for cgroup in tree.walk():
    print_cgroup(cgroup)

def print_cgroup(cgroup_node):
  # Don't print subsystem roots
  if cgroup_node.node_type == cgroup_node.NODE_CONTROLLER_ROOT: return
  if cgroup_node.controller_type == 'memory':
    # If using nested groups, 'total_rss' from cgroup_node.controller.stats includes nested allocations
    print('cgroup {0}  Memory Limit: {1}MB  Current Usage: {2}MB  OOM Count: {3}'.format(
     cgroup_node.path,
     cgroup_node.controller.limit_in_bytes/1048576,
     cgroup_node.controller.usage_in_bytes/1048576,
     cgroup_node.controller.failcnt,
     ))
    pids = cgroup_node.controller.procs
    if not pids: return
    print('    PID  Mem (MB)  Username  Process')
    for pid in pids:
      try:
        proc = psutil.Process(pid)
        proc_cmdline = proc.cmdline()
        if len(proc_cmdline) == 0: continue
        proc_cmdline = proc_cmdline[0]
        proc_username = proc.username()
        proc_meminfo = proc.memory_info_ex()
        proc_mem = (proc_meminfo.rss - proc_meminfo.shared)/1048576
        print('  {0:>5}  {1:>8}  {2:>8}  {3}'.format(pid, proc_mem, proc_username, proc_cmdline))
      except psutil.NoSuchProcess: continue

if __name__ == '__main__':
  print_all_cgroups()
