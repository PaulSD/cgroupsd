# cgroups Management Daemon

This program is basically a combination of the standard cgconfig and cgrulesengd programs, but implemented in Python to allow for easy extensibility.  For example, this may be used to dynamically define and assign cgroups to Rails web applications running under an Apache / Passenger server, which is not possible with the existing cgconfig and cgrulesengd programs.

## Prerequisites:

* argparse: `` `sudo apt-get install python-argparse` or `sudo yum install python-argparse` ``
* libnl: `` `sudo apt-get install libnl-3-200` or `sudo yum install libnl3` ``
* libnl headers: `` `sudo apt-get install libnl-3-dev` or `sudo yum install libnl3-devel` ``
* cffi (v0.8.2 or later): `` `sudo apt-get install python-cffi` or `sudo yum install python-pip ; sudo pip install cffi` ``
* psutil (v2 or later): `` `sudo apt-get install python-psutil` or `sudo yum install python-pip ; sudo pip install psutil` ``
* cgroupspy: `` `sudo apt-get install python-pip ; sudo pip install cgroupspy` or `sudo yum install python-pip ; sudo pip install cgroupspy` ``

## Configuration

See the comments in [etc/cgroupsd_handlers.py](tree/master/etc/cgroupsd_handlers.py) for configuration/customization.

## License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/).
