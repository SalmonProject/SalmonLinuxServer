//Copyright 2015 The Salmon Censorship Circumvention Project
//
//This file is part of the Salmon Server (GNU/Linux).
//
//The Salmon Server (GNU/Linux) is free software; you can redistribute it and / or
//modify it under the terms of the GNU General Public License as published by
//the Free Software Foundation; either version 3 of the License, or
//(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//GNU General Public License for more details.
//
//The full text of the license can be found at:
//http://www.gnu.org/licenses/gpl.html



#include "constants.h"
#include "globals.h"

//The password the wrapper uses to identify itself to the directory server.
//IMPORTANT NOTE: currently NOT null terminated!!! We're just using memcpy(PASSWORD_LENGTH).
char gDirServPassword[DIRSERV_PASSWORD_LENGTH];
//The SoftEther server's IPSec PSK
char gMyPSK[IPSEC_PSK_LENGTH+1];

//Time the server was last started. Gets set at the end of a successful serverUp().
//Used to decide whether to respond "wasdown" (started <5 minutes ago) to block checks.
time_t gTimeStartedAt;

//Whether to use SoftEther's built-in "Secure NAT". (Currently, Windows must use it).
BOOL gUseSoftEtherSecureNAT = TRUE;
//If we're doing iptables NAT on Linux, this is a string of the first 3 octets of the
//tap interface. Install script currently chooses gTapBaseIP="192.168.176" by default.
char* gTapBaseIP = 0;

//One string for each line that is supposed to be in salmon_settings. malloc()'d and
//set by loadSettings(), free()d by freeStuff().
char* gOfferedBW = 0;//string integer, in KB/s
char* gServerUpTime = 0;
char* gServerDownTime = 0;
char* gAdminPass = 0;


