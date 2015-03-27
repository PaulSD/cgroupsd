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
# cgroups Management Daemon Process Handlers
#
# This file simply imports and instantiates other process handler scripts.  To customize the
# behavior of cgroupsd, install or create relevant handler scripts in this directory, then import
# and instantiate them as shown below.  See example_handler.py for an example handler script.
#

#from example_handler import ExampleHandler
#eh = ExampleHandler()

from rails_handler import RailsHandler
rh = RailsHandler()
