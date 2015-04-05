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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "constants.h"
#include "globals.h"

#include "utility.h"


//daemonize! thank you Devin Watson: http://www.netzmafia.de/skripten/unix/linux-daemon-howto.html
void daemonize()
{
	//Our process ID and Session ID
	pid_t pid, sid;

	//Fork off the parent process
	pid = fork();
	if(pid < 0)
		exit(EXIT_FAILURE);
	//If we got a good PID, then we can exit the parent process.
	if(pid > 0)
		exit(EXIT_SUCCESS);

	//Change the file mode mask
	umask(0);

	//Create a new SID for the child process
	sid = setsid();
	if(sid < 0)
		exit(EXIT_FAILURE);

	//Change the current working directory
	if((chdir("/")) < 0)
		exit(EXIT_FAILURE);

	//Close out the standard file descriptors
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}

void logToFile(const char* theString, const char* theFile)
{
	time_t tempTime;
	time(&tempTime);
	char* timeStr = ctime(&tempTime);
	if(strchr(timeStr, '\n'))
		*strchr(timeStr, '\n') = 0;

	FILE* theLogFile = fopen(theFile, "at");
	fwrite(timeStr, 1, strlen(timeStr), theLogFile);
	fwrite(": ", 1, 2, theLogFile);
	fwrite(theString, 1, strlen(theString), theLogFile);
	fwrite("\n", 1, 1, theLogFile);
	fclose(theLogFile);
}
void logMajorNotification(const char* theString)
{
	logToFile(theString, "/var/lib/salmon/SALMON_MAJOR_NOTIFICATION.txt");
}
void logError(const char* theString)
{
	logToFile(theString, "/var/lib/salmon/SALMON_ERRORS.txt");
}

void uninitTLS();
void exitErrorNoLog()
{
	freeStuff();
	uninitTLS();
	exit(1);
}
void exitError(const char* errStr)
{
	logError(errStr);
	exitErrorNoLog();
}

void genPassword()
{
	//NOTE yes urandom is plenty good, this password is really not need-to-be-paranoid level important
	FILE* readUrandom = fopen("/dev/urandom", "rb");
	if(!readUrandom)
		exitError("Cannot read from /dev/urandom!");
	int charsGotten=0;
	while(charsGotten < DIRSERV_PASSWORD_LENGTH)
	{
		int tryChar = fgetc(readUrandom);
		if(tryChar > 32 && tryChar < 127)
		{
			gDirServPassword[charsGotten] = (char)tryChar;
			charsGotten++;
		}
	}

	FILE* writePW = fopen("/var/lib/salmon/salmon_dirserv_pw", "wt");
	if(!writePW)
		exitError("Could not access /var/lib/salmon/salmon_dirserv_pw! Please ensure that it exists, with permissions set to rw-rw-rw (666).");
	
	fwrite(gDirServPassword, 1, DIRSERV_PASSWORD_LENGTH, writePW);
	//I'm just going to throw the IPSec PSK in here too, because it and the dirserv pw are both
	//fundamentally the same - a random string shared with the dir server at registration.
	charsGotten=0;
	gMyPSK[IPSEC_PSK_LENGTH] = 0;
	while(charsGotten < IPSEC_PSK_LENGTH)
	{
		int tryChar = fgetc(readUrandom);
		if(isalnum(tryChar)) //this gets passed into system(), so keep it clean
		{
			gMyPSK[charsGotten] = (char)tryChar;
			charsGotten++;
		}
	}
	fwrite(gMyPSK, 1, IPSEC_PSK_LENGTH, writePW);
	fclose(writePW);
	fclose(readUrandom);
}

int readPWPSK()
{
	//NOTE this program is supposed to generate and store a dirserv pw if there isn't one yet.
	//	so why does it make sense to fail if you can't read this file? because the installation
	//	process is supposed to ensure that it exists, with the correct permissions. (Linux version.)
	FILE* readPW = fopen("/var/lib/salmon/salmon_dirserv_pw", "rt");
	if(!readPW)
		exitError("Could not access /var/lib/salmon/salmon_dirserv_pw! Please ensure that it exists, with permissions set to rw-rw-rw- (666).");
	
	int pwReadLen = fread(gDirServPassword, 1, DIRSERV_PASSWORD_LENGTH, readPW);
	memset(gMyPSK, 0, IPSEC_PSK_LENGTH);
	pwReadLen += fread(gMyPSK, 1, IPSEC_PSK_LENGTH, readPW);
	gMyPSK[IPSEC_PSK_LENGTH] = 0;
	fclose(readPW);
	
	return pwReadLen;
}

void ensureCertFile()
{
	//ensure softether correctly exported its automatically generated certificate to
	//     /var/lib/salmon_settings/my_softether_cert.crt
	FILE* testCertFile = fopen("/var/lib/salmon/my_softether_cert.crt", "rt");
	//here, i would try to get softether to export it. but, due to softether's "refuses to accept
	//absolute filepaths in general, and apparently refuses to accept any path from this daemon"
	//thing, that's not possible. fortunately, short of careless user intervention, there's no 
	//way this certificate (created at installation, owned by root, permissions 444) is going to
	//get messed up.
	if(!testCertFile)
		exitError("Could not access /var/lib/salmon/my_softether_cert.crt! Please ensure that it exists, with permissions set to r--r--r-- (444).");

	fclose(testCertFile);
}

void loadSettings()
{
	BOOL useDefaults = TRUE;

	FILE* readSettings = fopen("/var/lib/salmon/salmon_settings", "rt");
	if(readSettings)
	{
		useDefaults = FALSE;

		//when loadSettings() is called, gOfferedBW etc should all be null, so getline() will malloc() for us.
		size_t dummyLen = 0;
		//NOTE these aren't the final time strings; see below
		if(getline(&gOfferedBW, &dummyLen, readSettings)<=1)//getline's count includes newline
			useDefaults = TRUE;
		dummyLen = 0;
		if(getline(&gServerUpTime, &dummyLen, readSettings)<=2)
			useDefaults = TRUE;
		dummyLen = 0;
		if(getline(&gServerDownTime, &dummyLen, readSettings)<=2)
			useDefaults = TRUE;
		dummyLen = 0;
		
		//we really need that password!
		if(getline(&gAdminPass, &dummyLen, readSettings)<=2)
			exitError("Invalid Softether admin password! Please reinstall the whole Salmon+Softether package.");
		
		fclose(readSettings);
		
		if(strchr(gOfferedBW, '\n'))
			*strchr(gOfferedBW, '\n')=0;
		if(strchr(gServerUpTime, '\n'))
			*strchr(gServerUpTime, '\n')=0;
		if(strchr(gServerDownTime, '\n'))
			*strchr(gServerDownTime, '\n')=0;
		if(strchr(gAdminPass, '\n'))
			*strchr(gAdminPass, '\n')=0;
	}
	else
		exitError("/var/lib/salmon/salmon_settings is missing! Please reinstall the whole Salmon+Softether package.");

	//NOTE since getline() was definitely called on gOfferedBW and serverUp/DownTime, they have
	//	definitely been malloc()'d, so it's safe to just free them without checking if they're still 0,
	//	and also safe to call strstr() on them.
	if(useDefaults)
	{
		free(gOfferedBW);
		free(gServerUpTime);
		free(gServerDownTime);
		gOfferedBW = strdup("100");
		gServerUpTime = strdup("NEVER");
		gServerDownTime = strdup("NEVER");
	}
	else if(strstr(gServerUpTime, "NEVER") || strstr(gServerDownTime, "NEVER"))
	{
		free(gServerUpTime);
		free(gServerDownTime);
		gServerUpTime = strdup("NEVER");
		gServerDownTime = strdup("NEVER");
	}
	else
	{
		//NOTE expected time format: 2014-07-12T01:01:00
		//     what will be in file (if not NEVER): 01:01
		//so, tack on that other stuff in front and back.
		char* temp = malloc(strlen("2014-07-01T")+strlen(gServerUpTime)+strlen(":00")+1);
		sprintf(temp, "2014-07-01T%s:00", gServerUpTime);
		free(gServerUpTime);
		gServerUpTime = temp;

		//NOTE no, we don't need to worry about adding to the date if the times wrap around
		temp = malloc(strlen("2014-07-01T")+strlen(gServerDownTime)+strlen(":00")+1);
		sprintf(temp, "2014-07-01T%s:00", gServerDownTime);
		free(gServerDownTime);
		gServerDownTime = temp;
	}
	
	gUseSoftEtherSecureNAT=FALSE;
	FILE* readNATsetting = fopen("/var/lib/salmon/softetherSecureNAT", "rt");
	if(readNATsetting)
	{
		char tempNATbuf[10];
		memset(tempNATbuf, 0, 10);
		fread(tempNATbuf, 1, 5, readNATsetting);
		fclose(readNATsetting);
		if(!strncmp(tempNATbuf, "yes", 3))
			gUseSoftEtherSecureNAT=TRUE;
	}
	
	if(!gUseSoftEtherSecureNAT)
	{
		FILE* readBaseTapIP = fopen("/var/lib/salmon/tapIP", "rt");
		if(readBaseTapIP)
		{
			size_t dummyLen = 0;
			getline(&gTapBaseIP, &dummyLen, readBaseTapIP);
			fclose(readBaseTapIP);
			if(strchr(gTapBaseIP, '\n'))
				*strchr(gTapBaseIP, '\n')=0;
		}
		else
			logError("Could not read /var/lib/salmon/tapIP");
	}
	else
	{
		//NOTE: this is used in dhcpset, regardless of whether real NAT or SecureNAT is used!
		gTapBaseIP = strdup("192.168.176");
	}
}


void wipePassword()
{
	FILE* wipePW = fopen("/var/lib/salmon/salmon_dirserv_pw", "wt");
	if(!wipePW)
		logError("Could not open password file for wiping.");
	else
	{
		fwrite("invalidpass", 1, 11, wipePW);
		fclose(wipePW);
	}
}


void hton64(uint64_t* output, uint64_t input)
{
	int checkEndianness = 1;
	if(*(char*)&checkEndianness != 1)//big endian
	{
		*output = input;
		return;
	}
	
	char* inBytes = (char*)&input;
	char* outBytes = (char*)output;
	int i=0;
	for(i=0;i<8;i++)
		outBytes[i] = inBytes[7-i];
}


uint16_t writeSendLen(char* dest, char* strlenOfThis)
{
	unsigned long int theLen = strlen(strlenOfThis);
	if(theLen > 65535)
	{
		logError("Tried to send a string longer than 65535 to directory server.");
		return htons(65535);
	}
	uint16_t toSend = (uint16_t)theLen;
	uint16_t netOrder = htons(toSend);
	memcpy(dest, &netOrder, 2);
	return toSend;
}

void freeStuff()
{
	if(gOfferedBW)
		free(gOfferedBW);
	if(gServerUpTime)
		free(gServerUpTime);
	if(gServerDownTime)
		free(gServerDownTime);
	if(gAdminPass)
		free(gAdminPass);
	if(gTapBaseIP)
		free(gTapBaseIP);
	gOfferedBW = gServerUpTime = gServerDownTime = gAdminPass = gTapBaseIP = 0;
}
