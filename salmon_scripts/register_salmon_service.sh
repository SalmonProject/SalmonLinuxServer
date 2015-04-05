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

hasUpdateRCd=`which update-rc.d`
hasChkconfig=`which chkconfig`

if [ -n "$hasUpdateRCd" ] ; then
	cp salmonandsoftether_rc /etc/init.d/salmonandsoftether
	chmod 755 /etc/init.d/salmonandsoftether
	update-rc.d salmonandsoftether defaults
	echo "Salmon and SoftEther have been registered as a service."
elif [ -n "$hasChkconfig" ] ; then
	cp salmonandsoftether_chkconfig /etc/init.d/salmonandsoftether
	chmod 755 /etc/init.d/salmonandsoftether
	chkconfig --add salmonandsoftether
	echo "Salmon and SoftEther have been registered as a service."
else
	echo ""
	echo ""
	echo ""
	echo ""
	echo "**********************************************"
	echo "WARNING! neither update-rc.d nor chkconfig is"
	echo "   present. Salmon has not been installed as"
	echo "     a service, and will not start on boot."
	echo "     The Salmon system can be started by"
	echo "     /usr/local/vpnserver/vpnserver start"
	echo "                 followed by"
	echo "         /usr/local/vpnserver/salmond."
	echo "**********************************************"
	echo ""
	echo ""
	echo ""
	echo ""
fi
