#!/bin/sh

#Copyright 2015 The Salmon Censorship Circumvention Project

#This file is part of the Salmon Server (GNU/Linux).

#The Salmon Server (GNU/Linux) is free software; you can redistribute it and / or
#modify it under the terms of the GNU General Public License as published by
#the Free Software Foundation; either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#GNU General Public License for more details.

#The full text of the license can be found at:
#http://www.gnu.org/licenses/gpl.html

if [ "$(id -u)" != "0" ]; then
	echo "You must run this script as root: try sudo ./uninstall.sh"
	exit 1
fi

service salmonandsoftether stop

hasUpdateRCd=`which update-rc.d`
hasChkconfig=`which chkconfig`

if [ -n "$hasUpdateRCd" ]; then
	rm /etc/init.d/salmonandsoftether
	update-rc.d -f salmonandsoftether remove
	echo "Salmon and SoftEther are no longer registered as a service."
elif [ -n "$hasChkconfig" ]; then
	rm /etc/init.d/salmonandsoftether
	chkconfig --del salmonandsoftether
	echo "Salmon and SoftEther are no longer registered as a service."
fi
