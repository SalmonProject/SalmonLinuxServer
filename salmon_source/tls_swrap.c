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
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "polarssl/ssl.h"
#include "polarssl/sha1.h"

#include "constants.h"
#include "globals.h"
#include "connect_tls.h"
#include "connection_logic.h"
#include "utility.h"


void usageReporter(void* dummyarg)
{
	//NOTE max email address length is 254, so this should be fine.
	char curUsageUserName[300];
	memset(curUsageUserName, 0, 300);
	sleep(10);

	char* usageReportRaw = 0;
	while(1)
	{
		usageReportRaw = malloc(1024*64);
		char* usageReport = usageReportRaw+sizeof(uint16_t);
		char toExec[EXEC_VPNCMD_BUFSIZE];

		sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:salmon /password:%s /cmd userlist", gAdminPass);
		FILE* userLister = popen(toExec, "r");
		if(!userLister)
		{
			logError("Could not run userlist on SoftEther.");
			goto Bed;
		}
		usageReport[0] = 0;
		char* lineGetter = 0;
		size_t dummyLen;

		while(getline(&lineGetter, &dummyLen, userLister) > 0)
		{
			if(strstr(lineGetter, "User Name") && strchr(lineGetter, '|'))
			{
				strcpy(curUsageUserName, strchr(lineGetter, '|')+1);
				if(strchr(curUsageUserName, '\n'))
					*strchr(curUsageUserName, '\n')=0;
			}
			else if(strstr(lineGetter, "Last Login") && strchr(lineGetter, '|'))
			{
				if(strstr(lineGetter, "(None)"))
				{
					//curUserName gets score 0
					strcat(usageReport, curUsageUserName);
					strcat(usageReport, ":..@..:");
					strcat(usageReport, "0\n");
				}
				//very basic sanity check on format
				else if(strchr(lineGetter, ')') && strchr(lineGetter, '-') && strchr(lineGetter, ':'))
				{
					//time to extract the date and time. pretty ugly, but it works!
					char* getDate = strchr(lineGetter, '|')+1;
					char dateStr[100];
					memset(dateStr, 0, 100);
					strcpy(dateStr, getDate);
					if(!strchr(dateStr, ' '))
						goto Bed;
					*strchr(dateStr, ' ') = 0;
					char* getTime = strchr(getDate, ')');
					while(*getTime < '0' || *getTime > '9')
						getTime++;
					
					char timeStr[30];
					strcpy(timeStr, getTime);
					if(strchr(timeStr, '\n'))
						*strchr(timeStr, '\n')=0;

					char dateTimeStr[60];
					strcpy(dateTimeStr, dateStr);
					strcat(dateTimeStr, " ");
					strcat(dateTimeStr, timeStr);

					struct tm tempTime;
					memset(&tempTime, 0, sizeof(struct tm));
					strptime(dateTimeStr, "%Y-%m-%d %H:%M:%S", &tempTime);
					time_t timeSSE = mktime(&tempTime);

					//put the user's name in the report...
					strcat(usageReport, curUsageUserName);
					strcat(usageReport, ":..@..:");
					//now check last connection time to decide what score to give
					//curUserName gets score 100 if connected within the last 2 days, 25 else
					if(time(0) - timeSSE < 60 * 60 * 24 * 2)
						strcat(usageReport, "100\n");
					else
						strcat(usageReport, "25\n");
				}
				else
					logError("SoftEther's UserList gave us a weirdly formatted Last Login field...");
			}
		}
		pclose(userLister);
		

		
		
		//the usage report is almost finished: now just tack on the final item, total bytes.
		long long unsigned int totalKBytes=0; //kilo, not kebi: power of 10, not 2.
		sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /password:%s /cmd hublist", gAdminPass);
		FILE* hubLister = popen(toExec, "r");
		if(!hubLister)
		{
			logError("Could not run hublist on SoftEther.");
			goto Bed;
		}
		BOOL foundSalmonHub=FALSE;
		while(getline(&lineGetter, &dummyLen, hubLister) > 0)
		{
			if(foundSalmonHub && strstr(lineGetter, "Transfer Bytes"))
			{
				char* numberStart = strchr(lineGetter, '|')+1;
				char withoutCommas[60];
				memset(withoutCommas, 0, 60);
				int i;
				for(i=0; i<60 && (*numberStart >= '0' && *numberStart <= '9' || *numberStart == ','); numberStart++)
					if(*numberStart >= '0' && *numberStart <= '9')
					{
						withoutCommas[i] = *numberStart;
						i++;
					}

				//divide by 2 because softether appears to count both incoming and outgoing bytes;
				//there is of course one incoming AND one outgoing for each one of the user's bytes.
				//divide by 1000 to get KB: softether reports the number in bytes.
				totalKBytes = (strtoull(withoutCommas, 0, 10)/1000)/2;
				break;
			}
			else if(strstr(lineGetter, "Virtual Hub Name")&&strstr(lineGetter, "salmon"))
				foundSalmonHub=TRUE;
		}
		pclose(hubLister);
		
		
		
		char totalBytesLine[70];
		sprintf(totalBytesLine, ":.bw.@.bw.:%llu", totalKBytes);
		strcat(usageReport, totalBytesLine);
		if(lineGetter)
			free(lineGetter);





		//now we're done building the message. time to send it.
		int reportSocket;
		if(net_connect(&reportSocket, SERVER_NAME, SERVER_PORT) != 0)
		{
			//NOTE this isn't THAT bad. just skip this report, no error message.
			goto Bed;
		}
		ssl_context* sslReport = TLSwithDir(&reportSocket);
		if(!sslReport)
		{
			shutdownWaitTLS(sslReport, reportSocket);
			goto Bed;
		}
		char dirResponse = authenticateWithDir(sslReport, 'g');
		if(dirResponse=='K')
		{
			//NOTE NOTE now network order
			uint16_t bytesSending = writeSendLen(usageReportRaw, usageReport);
			sendTLS(sslReport, usageReportRaw, sizeof(uint16_t) + bytesSending);
		}
		else
		{
			//this is definitely bizarre, but just skip this report, no error message.
			shutdownWaitTLS(sslReport, reportSocket);
			goto Bed;
		}
		shutdownWaitTLS(sslReport, reportSocket);
		
		//in case IP address has changed without the server restarting
		tryServerUp();

Bed:
		free(usageReportRaw);
		sleep(60*60*24 + 60);
	}
}


//call with (0, -1) if you want it to connect from scratch, or (fd, 0) if you already have a socket but no ssl
BOOL tryRegisterHaveConn(ssl_context* ssl, int theSocket)
{
	int ourSocket = theSocket;
	if (ourSocket < 0 && net_connect(&ourSocket, SERVER_NAME, SERVER_PORT) != 0)
	{
		shutdownWaitTLS(ssl, theSocket);
		exitError("Could not connect to the directory server for registration.");
	}
	if (!ssl && !(ssl = TLSwithDir(&ourSocket)))
	{
		shutdownWaitTLS(ssl, theSocket);
		exitError("Could not TLS to the directory server for registration.");
	}
	//Fill gDirServPassword+gMyPSK, and save it the pw file. This overwrites any previous info, so we do it
	//only after a successful TLSwithDir(), so it's less likely we wipe out possibly useful info in doing a 
	//procedure that was going to fail anyways.
	genPassword();

	//Go through the registration process (authenticateWithDir() will use the newly generated pw)
	char dirResponse = authenticateWithDir(ssl, 'r');
	if (dirResponse == 'K')
	{
		BOOL amRegistered = registerSelf(ssl);
		shutdownWaitTLS(ssl, theSocket);
		return amRegistered;
	}
	else
	{
		shutdownWaitTLS(ssl, theSocket);
		return FALSE;
	}
}

//call with (0, -1) if you want it to connect from scratch, or (fd, 0) if you already have a socket but no ssl
BOOL tryServerUpHaveConn(ssl_context* ssl, int theSocket)
{
	int ourSocket = theSocket;
	if (ourSocket < 0 && net_connect(&ourSocket, SERVER_NAME, SERVER_PORT) != 0)
	{
		shutdownWaitTLS(ssl, theSocket);
		exitError("Could not connect to the directory server for serverUp.");
	}
	if (!ssl && !(ssl = TLSwithDir(&ourSocket)))
	{
		shutdownWaitTLS(ssl, theSocket);
		exitError("Could not TLS to the directory server for serverUp.");
	}

	char dirResponse = authenticateWithDir(ssl, 'u');
	if (dirResponse == 'K')
	{
		BOOL upSucceeded = serverUp(ssl);
		shutdownWaitTLS(ssl, theSocket);
		return upSucceeded;
	}
	else
	{
		shutdownWaitTLS(ssl, theSocket);
		return FALSE;
	}
}

BOOL tryRegister() { return tryRegisterHaveConn(0, -1); }
BOOL tryServerUp() { return tryServerUpHaveConn(0, -1); }

//attempt to do startup stuff, and then go into the main connection accepting loop.
//the startup stuff is to send a server-up message, or register if necessary.
int main()
{
	daemonize();
	
	struct sigaction siggy;
	memset(&siggy, 0, sizeof(struct sigaction));
	siggy.sa_handler = gracefulExit;
	sigaction(SIGTERM, &siggy, NULL);
	sigaction(SIGINT, &siggy, NULL);

	
	
	//======================================================================
	//read settings files: dirserv pw, PSK, our certificate, offered BW, etc
	//======================================================================
	
	//Read into gDirServPassword and gMyPSK. They come in the same file, and this
	//function reports how many bytes it got out of the file, so we can check it below.
	int pwReadLen = readPWPSK();

	//Read into gAdminPassword, gOfferedBW etc from /var/lib/salmon/salmon_settings.
	//Fail if we didn't get gAdminPassword. If any other info looks wrong, go forward with default values.
	loadSettings();
	
	//Ensure SoftEther correctly exported its automatically generated certificate at install time, writing
	//it to /var/lib/salmon/my_softether_cert.crt. Error out if not (Windows version tries to recover).
	ensureCertFile();
	
	
	
	
	//====================================================================
	//connect to dir server, either to register, or to tell it we're back
	//====================================================================
	
	//just give up if we can't initTLS().
	if(initTLS())
		exitError("Failed to initialize PolarSSL.");
	
	//If can't connect to directory server, that might be because the server computer's internet connection
	//isn't up yet. After all, this program runs at startup. Even though normal networking might be all up
	//and running by the time this is started, what about a USB wireless card, or something? So, just
	//to be safe, keep trying over the course of a minute.
	int theSocket;
	int netConRes = -1;
	int connectTries = 0;
	time_t firstConTryTime = time(0);
	while(netConRes != 0 && connectTries < 6 && time(0) - firstConTryTime < 60)
	{
		netConRes = net_connect(&theSocket, SERVER_NAME, SERVER_PORT);
		connectTries++;
		if(netConRes != 0)
			sleep(10);
	}
	if(connectTries >= 6 && netConRes != 0 && net_connect(&theSocket, SERVER_NAME, SERVER_PORT) != 0)
		exitError("Could not connect to the directory server.");
	
	ssl_context* ssl = TLSwithDir(&theSocket);
	if(!ssl)
	{
		//NOTE ok to call shutdownTLS on null ssl because it's checked for in the function.
		//(we are calling shutdown to close the net_connect()'d theSocket)
		shutdownTLS(ssl, theSocket);
		exitError("Failed to establish TLS session with directory server.");
	}
	

	//if we don't have a good looking salmon_dirserv_pw file, then try to register
	if (pwReadLen != DIRSERV_PASSWORD_LENGTH + IPSEC_PSK_LENGTH)
	{
		if(tryRegisterHaveConn(ssl, theSocket))
		{
			if(!tryServerUp())
				exitError("Registered, but directory server responded weirdly to our server-up message.");
		}
		else
			exitError("Registration with a newly generated password failed, even though we were able to correctly communicate with the directory server.");
	}
	else //report in to the dir as an existing server
	{
		if (!tryServerUpHaveConn(ssl, theSocket))
		{
			if (tryRegister())
			{
				if(!tryServerUp())
					exitError("We had a password but failed to server-up, then succeeded with a fresh registration, but the server-up with the new password also failed... very strange.");
			}
			else
				exitError("We had a password and connected to the directory server, but the server-up and fallback re-register attempts both failed.");
		}
	}
	
	
	//==========================
	//post-dirserv-contact logic
	//==========================
	
	gTimeStartedAt = time(0);

	pthread_t thread_id;
	pthread_create(&thread_id, NULL, usageReporter, (void*)0);

	//handle any messages the directory server sends us
	acceptConnections();
	
	//it shouldn't be possible to reach this:
	logError("The main accept-TCP-connections loop died! Exiting.");
	exit(EXIT_FAILURE);
}
