#!/bin/bash

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

#Installation script for the Salmon VPN server package: installs+configures
#the SoftEther VPN server and the Salmon VPN server wrapper. "Configuration"
#includes setting up iptables-based NAT, if possible.

if [ "$(id -u)" != "0" ] ; then
	echo "You must run this script as root: try sudo ./install_salmon.sh"
	exit 1
fi

if [ $(uname -m) != 'x86_64' ]; then
	echo "This is the 64-bit Salmon+SoftEther package, but your machine is 32-bit! Aborting."
	exit 1
fi

#This script believes iptables NAT is possible if the iptable_nat kernel 
#module can be correctly loaded. If you would rather use SoftEther's 
#built-in "SecureNAT", set overrideToSoftEtherSecureNAT to yes. This might be
#useful if iptables NAT isn't working despite the module loading correctly.
#Generally speaking, the iptables way is much preferred: it has less CPU 
#overhead than SoftEther's SecureNAT, and if you _ARENT_ behind a typical 
#NATing home router, users likely won't be able to access the internet 
#through you if you use SecureNAT. Yes, that is very weird, I know :)

#***SET TO yes TO DISABLE IPTABLES NAT. YOU PROBABLY DON'T WANT TO DO THIS.****
overrideToSoftEtherSecureNAT="no"
#******************************************************************************

#let's do this early; if we do it after the makes, they've already seen a bunch
#of meaningless crap fly by the screen, and have maybe gone off to do something else
echo "*******************************************************************************"
echo "*******************************************************************************"
echo "How much bandwidth can you provide? This is limited by your upload bandwidth,"
echo "not download. Home internet connections typically have much higher down than"
echo "up bandwidth, and the VPN connections use both up and down equally. A nice"
echo "side effect: typical internet activities like web browsing and video streaming"
echo "are essentially unaffected by hosting a VPN server."
echo ""
echo "In KB/s, how much upload bandwidth can you spare? (100 is likely a good choice)"
uploadBW="garbage"
while [ -z `echo $uploadBW | grep "^[0-9]*$"` ] ; do
	read uploadBW
	if [ -z `echo $uploadBW | grep "^[0-9]*$"` ] ; then
		echo "Malformed bandwidth: please enter digits only. Units: kilobytes per second."
	fi
done
echo "*******************************************************************************"
echo "*******************************************************************************"

echo ""
echo ""
echo ""

echo "*******************************************************************************"
echo "*******************************************************************************"
echo "If you would be willing to try changing your IP address when a country blocks"
echo "your server, please enter an email address we can notify you at if such a block"
echo "were to happen. We won't share this address with anyone, or send any messages"
echo "to it other than 'you were blocked'. Blocks should be rare, so your server will"
echo "still be helpful to the system even if you don't provide an email address."
echo ""
echo "Enter email address [hit enter to skip]:"

notifyEmail=""
read notifyEmail
echo "*******************************************************************************"
echo "*******************************************************************************"


hasAptGet=`which apt-get`
hasYum=`which yum`
buildPolarSSL=""
if [ -n "$hasAptGet" ] ; then
	apt-get --yes install gcc make
	aptGetRes=`apt-get --yes install libpolarssl5 libpolarssl-dev 2>&1 | grep 'Unable to locate package'`
	if [ -n "$aptGetRes" ] ; then
		buildPolarSSL="yes"
	fi
elif [ -n "$hasYum" ] ; then
	yum install gcc make
	yum install polarssl polarssl-devel
else
	echo ""
	echo ""
	echo ""
	echo ""
	echo "********************************************"
	echo "WARNING! neither apt-get nor yum is present."
	echo "The install script will now attempt to build"
	echo "PolarSSL from source. If that fails, you'll"
	echo "  need to install the polarssl library and"
	echo "  headers yourself. Hit enter to continue."
	echo "********************************************"
	echo ""
	echo ""
	echo ""
	echo ""
	buildPolarSSL="yes"
	read dummyread
fi

if [ -n "$buildPolarSSL" ] ; then
	echo ""
	echo ""
	echo ""
	echo ""
	echo "********************************************"
	echo "   NOW ATTEMPTING TO BUILD PolarSSL 1.3.9."
	echo "********************************************"
	echo ""
	echo ""
	echo ""
	echo ""
	hasCMake=`which cmake`
	if [ -z "$hasCMake" ] ; then
		if [ -n "$hasAptGet" ] ; then
			apt-get --yes install cmake
		elif [ -n "$hasYum" ] ; then
			yum install cmake
		else
			echo ""
			echo ""
			echo ""
			echo ""
			echo "********************************************"
			echo "ERROR: you don't have cmake installed. The"
			echo "installation will now abort. Install cmake"
			echo "     and start the installation again."
			echo "********************************************"
			echo ""
			echo ""
			echo ""
			echo ""
			exit 1
		fi
	fi
	tar xvf polarssl-1.3.9-gpl.tgz
	cd polarssl-1.3.9
	cmake .
	make
	make install
	cd ..
fi

make
make salmon


#make the binaries dir, and copy the binaries there
mkdir /usr/local/vpnserver
cp vpnserver /usr/local/vpnserver
cp vpncmd /usr/local/vpnserver
cp hamcore.se2 /usr/local/vpnserver
cp salmond /usr/local/vpnserver
chmod 755 /usr/local/vpnserver/vpncmd

#check whether iptables NAT is possible. make the salmon settings dir so that
#we can save some config info, starting with iptables NAT usability.
mkdir /var/lib/salmon
modprobe ip_tables
modprobe iptable_nat
iptableNatLoaded=`lsmod | grep '^iptable_nat'`
if [ -z "$iptableNatLoaded" ] ; then
	overrideToSoftEtherSecureNAT="yes"
	echo "yes" >/var/lib/salmon/softetherSecureNAT
else
	echo "no" >/var/lib/salmon/softetherSecureNAT
fi
chmod 444 /var/lib/salmon/softetherSecureNAT

#copy various settings to their proper places
touch /var/lib/salmon/salmon_dirserv_pw
touch /var/lib/salmon/SALMON_ERRORS.txt
touch /var/lib/salmon/SALMON_MAJOR_NOTIFICATION.txt


#dirserv_pw and log files can change, so keep them world writeable
chmod 666 /var/lib/salmon/salmon_dirserv_pw
chmod 666 /var/lib/salmon/SALMON_ERRORS.txt
chmod 666 /var/lib/salmon/SALMON_MAJOR_NOTIFICATION.txt
cp salmon_dirserv.crt /var/lib/salmon
chmod 444 /var/lib/salmon/salmon_dirserv.crt
echo ~ >/var/lib/salmon/salmon_home_dir
chmod 644 /var/lib/salmon/salmon_home_dir
touch /var/lib/salmon/salmon_settings

if [ -n "$notifyEmail" ] ; then
	echo "$notifyEmail" >/var/lib/salmon/notify_email
	chmod 666 /var/lib/salmon/notify_email
fi

echo "$uploadBW" >/var/lib/salmon/salmon_settings
echo "NEVER" >>/var/lib/salmon/salmon_settings
echo "NEVER" >>/var/lib/salmon/salmon_settings
chmod 644 /var/lib/salmon/salmon_settings
touch /var/lib/salmon/salmon_settings_guide
echo "First line is your offered bandwidth, in KB/s. It is your upload bandwidth that will be the bottleneck. So long as you keep this number below your maximum upload bandwidth, you should see essentially no impact on normal web usage. Rough guide: 100 should not be too much for most people, and if you can stream HD video, 200 or more is likely appropriate." >/var/lib/salmon/salmon_settings_guide
echo " " >>/var/lib/salmon/salmon_settings_guide
echo "If you change this number after installation, please follow these steps to make the new value take effect: 1) run the 'unregister_salmon_service.sh' script, 2) run the 'register_salmon_service.sh' script, 3) start your server back up with 'sudo service salmonandsoftether start'" >>/var/lib/salmon/salmon_settings_guide
echo "=======================" >>/var/lib/salmon/salmon_settings_guide
echo "Second line is around when you usually turn this computer on every day. Format: hh:mm, e.g. 15:30 for 3:30PM, or 02:30 for 2:30AM." >>/var/lib/salmon/salmon_settings_guide
echo "=======================" >>/var/lib/salmon/salmon_settings_guide
echo "Third line is around when you usually turn this computer off every day. Same format as above. If this computer is always on, set both lines to NEVER." >>/var/lib/salmon/salmon_settings_guide
echo "=======================" >>/var/lib/salmon/salmon_settings_guide
echo "Fourth line is the admin password to your installation of SoftEther. You should leave this untouched, or things will break!" >>/var/lib/salmon/salmon_settings_guide
chmod 644 /var/lib/salmon/salmon_settings_guide
adminPass=`cat /dev/urandom | tr -dc A-Za-z0-9 | head --bytes=16`
echo "$adminPass" >>/var/lib/salmon/salmon_settings


#the binaries and settings files are in place, so now set up softether and salmon as a (joint) service
#(and set them to run at startup)
hasUpdateRCd=`which update-rc.d`
hasChkconfig=`which chkconfig`

if [ -n "$hasUpdateRCd" ] ; then
	cp salmon_scripts/salmonandsoftether_rc /etc/init.d/salmonandsoftether
	chmod 755 /etc/init.d/salmonandsoftether
	update-rc.d salmonandsoftether defaults
elif [ -n "$hasChkconfig" ] ; then
	cp salmon_scripts/salmonandsoftether_chkconfig /etc/init.d/salmonandsoftether
	chmod 755 /etc/init.d/salmonandsoftether
	chkconfig --add salmonandsoftether
else
	echo ""
	echo ""
	echo ""
	echo ""
	echo "**********************************************"
	echo "WARNING! neither update-rc.d nor chkconfig is"
	echo "   present. The install process can finish"
	echo "correctly, but salmond and SoftEther will not"
	echo "start automatically: neither now nor on boot."
	echo "     The Salmon system can be started by"
	echo "     /usr/local/vpnserver/vpnserver start"
	echo "                 followed by"
	echo "         /usr/local/vpnserver/salmond."
	echo ""
	echo "           Press enter to continue."
	echo "**********************************************"
	echo ""
	echo ""
	echo ""
	echo ""
	read dummyread
fi




if [ "$overrideToSoftEtherSecureNAT" != "yes" ] ; then

	#first, if /etc/sysctl.conf has ip_forward explicitly disabled, we should probably ask before changing it.
	checkGrepFwdDisabled=`grep '^net.ipv4.ip_forward=0' /etc/sysctl.conf`
	if [ -n "$checkGrepFwdDisabled" ] ; then
		echo "Your /etc/sysctl.conf has net.ipv4.ip_forward explicitly disabled."
		echo "In case you did this yourself, I don't want to change it without your"
		echo "permission. If you aren't sure how that setting was set / don't know"
		echo "what it means, it's probably safe to continue."
		echo ""
		echo "Should I set net.ipv4.ip_forward=1 and continue installing? (y/n)"
		read setIPForwardOk
		case "$setIPForwardOk" in
		[yY]) 
			echo "Enabling net.ipv4.ip_forward and continuing with installation."
		;;
		*)
			echo ""
			echo "Not enabling net.ipv4.ip_forward."
			echo "Salmon installation aborted."
			echo ""
			exit 0
		;;
		esac
	fi

	sysctl -w net.ipv4.ip_forward=1
	#first, uncomment the line, if it is there and commented.
	#then, check if it either already existed uncommented, or if our uncommenting worked.
	#if not, just append it.
	sed --in-place 's/^#net\.ipv4\.ip_forward=1$/net\.ipv4\.ip_forward=1/' /etc/sysctl.conf
	checkGrepIPfwd=`grep '^net.ipv4.ip_forward=1' /etc/sysctl.conf`
	if [ -z "$checkGrepIPfwd" ] ; then
		echo " " >>/etc/sysctl.conf
		echo "net.ipv4.ip_forward=1" >>/etc/sysctl.conf
	fi
fi


#settings are in place, softether and salmond are set up as services, which will run at startup,
#so now just do some final initialization of softether settings, and start them both up!
#NOTE can't do the next line with the service interface, since it would start/stop salmond as well
/usr/local/vpnserver/vpnserver start
echo "Setting SoftEther's admin password, please wait..."
#unfortunately, `vpnserver start` is perfectly content to return before its task is actually complete.
sleep 2
/usr/local/vpnserver/vpncmd /server localhost /cmd serverpasswordset $adminPass
echo "Please wait..."
#unfortunately, vpncmd is perfectly content to return before its task is actually complete.
sleep 2

if [ "$overrideToSoftEtherSecureNAT" != "yes" ] ; then
	#first, if tap_salmontap is present, can skip this tap+bridge creation stuff.
	tapSalmonExists=`ifconfig -a | grep tap_salmontap`
	if [ -z "$tapSalmonExists" ] ; then
		baseTapIP="192.168.176"
		#check if they're already using 192.168.176.0/24..... if so, use another 192.168
		alreadyUsed=`ifconfig -a | grep '192.168.176'`
		if [ -n "$alreadyUsed" ] ; then
			echo "Salmon defaults to using 192.168.176.0/24 for giving private"
			echo "NATed addresses to clients. It appears your network is assigning"
			echo "addresses in that range. Please choose another private /24 that"
			echo "Salmon can use. Enter it in the following format: 192.168.176"
			read baseTapIP
		fi
		echo "$baseTapIP" >/var/lib/salmon/tapIP
		chmod 644 /var/lib/salmon/tapIP

		#now, create the "salmon" hub. although we have ensureHub() in the server wrapper, this now
		#has to be done right here, because we need the hub to exist for bridgecreate to work the way we want
		/usr/local/vpnserver/vpncmd /server localhost /password:$adminPass /cmd hubcreate salmon /password:$adminPass
		echo "Please wait..."
		#unfortunately, vpncmd is perfectly content to return before its task is actually complete.
		sleep 2
		#Softether's "secure NAT" comprises a userspace (less efficient than iptables) NATer, and a DHCP
		#server. We want the DHCP server, but we're going to do NAT on our own. So, SecureNAT on, NAT off, DHCP on.
		#fortunately these next few don't depend on each other, so we don't need the stupid sleep hack
		/usr/local/vpnserver/vpncmd /server localhost /hub:salmon /password:$adminPass /cmd securenatenable
		/usr/local/vpnserver/vpncmd /server localhost /hub:salmon /password:$adminPass /cmd natdisable
		/usr/local/vpnserver/vpncmd /server localhost /hub:salmon /password:$adminPass /cmd dhcpenable
		#because we're doing our own NAT, the private IP addresses and the default gateway need to agree
		#with the IP address we are going to be assigning to the tap interface
		/usr/local/vpnserver/vpncmd /server localhost /hub:salmon /password:$adminPass /cmd dhcpset /START:$baseTapIP.2 /END:$baseTapIP.254 /MASK:255.255.255.0 /EXPIRE:7200 /GW:$baseTapIP.1 /DNS:8.8.8.8 /DNS2:8.8.4.4 /DOMAIN:none /LOG:yes


		bridgeListOut=`/usr/local/vpnserver/vpncmd /server localhost /password:$adminPass /cmd bridgelist | grep salmontap`
	
		if [ -z "$bridgeListOut" ] ; then
			/usr/local/vpnserver/vpncmd /server localhost /password:$adminPass /cmd bridgecreate salmon /DEVICE:salmontap /TAP:yes
			echo "Please wait..."
			#unfortunately, vpncmd is perfectly content to return before its task is actually complete.
			sleep 2
		fi
		ifconfig tap_salmontap $tapIP up
	fi
fi

#NOTE: this must be done on this initial softether-only run! can't do it after starting the whole
#	service, or else salmon errors out because the certificate isn't there.
echo "Exporting the certificate your SoftEther server generated..."
/usr/local/vpnserver/vpncmd /server localhost /password:$adminPass /cmd servercertget my_softether_cert.crt
sleep 2
mv my_softether_cert.crt /var/lib/salmon/my_softether_cert.crt
chmod 444 /var/lib/salmon/my_softether_cert.crt
echo "Certificate exported."

/usr/local/vpnserver/vpnserver stop
#Disable their dynamic DNS. Also knocks some SecureNAT stuff out, but that's fine, we set that ourselves.
sed --in-place 's/bool Disabled false/bool Disabled true/' /usr/local/vpnserver/vpn_server.config

#start them both up with the nice service interface!
service salmonandsoftether start


echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""
echo "***************************************************************************"
echo "                          INSTALLATION COMPLETE!"
echo "***************************************************************************"
echo " If you're behind a NAT box, such as a typical home router, please forward"
echo "TCP ports 7004 (Salmon server) and 443 (SoftEther VPN server), and UDP 500"
echo "        (helps establish L2TP for mobile devices) to this computer!"
echo ""
echo "           Salmon and SoftEther have been installed and started."
echo "                  They will start at every system startup."
echo ""
echo "      Thank you for helping the cause of free speech on the internet!"
echo ""
