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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include "constants.h"
#include "globals.h"

#include "connect_tls.h"
#include "connection_logic.h"


char authenticateWithDir(ssl_context* ssl, char command)
{
	//regardless of what we're going to be doing, we start by sending our password to authenticate ourself.
	//NOTE yes you send the password even if you're registering
	//NOTE NOTE for password, we don't do the ushort bytesSending thing, because it's fixed length
	sendTLS(ssl, gDirServPassword, DIRSERV_PASSWORD_LENGTH);
	sendTLS(ssl, &command, 1);

	//directory server tells us if we should continue, or if it's aborting.
	//NOTE the response should be 'K' for OK, or 'I' for invalid password (either the password wasn't
	//found and you're doing a server up, or the password WAS found and you're registering.)
	char dirStatusResponse='X';
	recvTLS(ssl, &dirStatusResponse, 1);
	return dirStatusResponse;
}

BOOL recvCredentialList(ssl_context* ssl, char* theBuf, unsigned int maxBufLen)
{
	int offset=0;
	int bytesRead=maxBufLen-1;
	BOOL credentialsGood=TRUE;

	for(;	bytesRead!=0
	        &&!strstr(theBuf, "@@@ENDLIST@@@@@@ENDLIST@@@@@@ENDLIST@@@")
	        &&offset<maxBufLen
	        ; offset+=bytesRead)
		bytesRead = recvTLS(ssl, theBuf+offset, (maxBufLen-1)-offset);
	
	theBuf[offset] = 0;
	
	char* tempstrstropt;
	if((tempstrstropt=strstr(theBuf, "@@@ENDLIST@@@@@@ENDLIST@@@@@@ENDLIST@@@")))
	{
		*tempstrstropt=0;
	}
	else
		credentialsGood=FALSE;

	return credentialsGood;
}

//attempts to register with the dir server as a new server. returns 0 if not successful.
BOOL registerSelf(ssl_context* ssl)
{
	//register. start with our password (which server won't have in its db), then give command 'r'.
	//(NOTE: password has already been sent at this point.)
	char theMsg[6000];
	char* msgTextStart = theMsg+sizeof(uint16_t);
	memset(msgTextStart, 0, 6000-sizeof(uint16_t));
	sprintf(msgTextStart, "%s\n%s\n%s\n%s\n", gOfferedBW, gServerUpTime, gServerDownTime, gMyPSK);
	
	FILE* readNotifyEmail = fopen("/var/lib/salmon/notify_email", "rt");
	if(!readNotifyEmail)
		strcat(msgTextStart, "!#$%^NONE!#$%^\n");
	else
	{
		char theEmailAddr[300];
		int charsRead = fread(theEmailAddr, 1, 299, readNotifyEmail);
		theEmailAddr[charsRead] = 0;
		fclose(readNotifyEmail);
		if(strchr(theEmailAddr, '\n'))
			*strchr(theEmailAddr, '\n')=0;
		strcat(msgTextStart, theEmailAddr);
		strcat(msgTextStart, "\n");
	}

	FILE* readSoftetherCert = fopen("/var/lib/salmon/my_softether_cert.crt", "rt");
	if(!readSoftetherCert)
	{
		logError("Somehow ended up trying to registerSelf() without a valid certificate.");
		return FALSE;
	}
	fread(msgTextStart+strlen(msgTextStart), 1, (6000-sizeof(uint16_t)) - strlen(msgTextStart), readSoftetherCert);
	fclose(readSoftetherCert);

	//ensure the message we send ends with a \n
	if(msgTextStart[strlen(msgTextStart)-1]!='\n')
		strcat(msgTextStart, "\n");

	//do a send into vibe's fixed-size recv
	uint16_t bytesSending = writeSendLen(theMsg, msgTextStart);
	sendTLS(ssl, theMsg, sizeof(uint16_t) + bytesSending);

	char recvStatus[200];
	memset(recvStatus, 0, 200);
	recvTLS(ssl, recvStatus, 199);

	return strncmp(recvStatus, "OK", 2) ? FALSE : TRUE;
}

BOOL serverUp(ssl_context* ssl)
{
	//say "going up": send 'u', then our offered bandwidth and times of day
	char theMsg[10000];
	char* msgTextStart = theMsg+sizeof(uint16_t);

	sprintf(msgTextStart, "%s\n%s\n%s\n", gOfferedBW, gServerUpTime, gServerDownTime);

	//do a send into vibe's fixed-size recv
	uint16_t bytesSending = writeSendLen(theMsg, msgTextStart);
	sendTLS(ssl, theMsg, sizeof(uint16_t) + bytesSending);

	//now receive the list of credentials we should be accepting.
	memset(theMsg, 0, 10000);
	BOOL credentialsGood = recvCredentialList(ssl, theMsg, 10000);

	if(credentialsGood)
		setAcceptedCredentials(theMsg);
	else
		logError("Directory server gave us a malformed credentials list...");

	return TRUE;
}

void respondAreYouStillThere(ssl_context* ssl)
{
	char pingReply[200];
	char* pingReplyText = pingReply+sizeof(uint16_t);
	memset(pingReply, 0, 200);

	sprintf(pingReplyText, "up\n%s\n%s\n%s\n", gOfferedBW, gServerUpTime, gServerDownTime);

	//we are sending to a vibedTLSreadBytes function, which expects an unsigned short int (2 bytes)
	//representing how many bytes will come after.
	uint16_t bytesSending = writeSendLen(pingReply, pingReplyText);
	sendTLS(ssl, pingReply, bytesSending + sizeof(uint16_t));

	memset(pingReply, 0, 200);
	int bytesRecvd = recvTLS(ssl, pingReply, 199);
	pingReply[bytesRecvd] = 0;
	//pingReply should now read "OK", but we don't really need to be sure... it was the
	//directory's idea to do this ping, so we don't care if it completes successfully.
}

void respondBlockCheck(ssl_context* ssl, int ourSocket)
{
	//parse format: bCN^xyzusernamexyz,   where b was already read out of the stream before this function.
	char recvbuf[200];
	memset(recvbuf, 0, 200);
	int bytesRecvd = recvTLS(ssl, recvbuf, 199);
	char whichCountry[3];
	memcpy(whichCountry, recvbuf, 2);
	whichCountry[2]=0;
	char userAccount[198];
	strcpy(userAccount, recvbuf+3);

	//semi-HACK: for now, the block check logic is "if the dir server can reach me and the person can't, i'm blocked."
	
	//however, just in case salmond is running but vpnserver isn't, we'll check whether vpnserver is up:
	BOOL vpnserverWasDown = FALSE;
	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /password:%s /cmd hublist", gAdminPass);
	FILE* hubLister = popen(toExec, "r");
	if(!hubLister)
	{
		logError("Could not run hublist on SoftEther.");
		return;
	}
	size_t lineGetterLen = 200;
	char* lineGetter = malloc(lineGetterLen);
	memset(lineGetter, 0, lineGetterLen);
	while(getline(&lineGetter, &lineGetterLen, hubLister) > 0)
	{
		if(strstr(lineGetter, "Error occurred"))
		{
			vpnserverWasDown = TRUE;
			break;
		}
	}
	pclose(hubLister);
	free(lineGetter);
	
	uint16_t bytesSending;
	if(vpnserverWasDown)
	{
		strcpy(recvbuf+sizeof(uint16_t), "wasdown");
		bytesSending = writeSendLen(recvbuf, recvbuf+sizeof(uint16_t));
		sendTLS(ssl, recvbuf, bytesSending+sizeof(uint16_t));
		logError("The directory asked us to check if we were blocked, and it turned out that\nSoftEther's vpnserver wasn't running. salmond will terminate now. Hopefully, the next time the salmonandsoftether service is started, things will get back to a working state.");
		
		//only shutdown here because we're exiting, otherwise, this function shouldn't try to handle that
		shutdownTLS(ssl, ourSocket);
		gracefulExit(0);
	}
	//if we started within the last 5 minutes, this block check is probably because someone tried to
	//talk to us while we were offline. report "wasdown" and just go on with your business.
	else if(time(0) - gTimeStartedAt < 300)
	{
		strcpy(recvbuf+sizeof(uint16_t), "wasdown");
		bytesSending = writeSendLen(recvbuf, recvbuf+sizeof(uint16_t));
		sendTLS(ssl, recvbuf, bytesSending+sizeof(uint16_t));
	}
	//verify that userAccount is an account in our softether salmon hub
	else if(!verifyUserAccount(userAccount))
	{
		//if we didn't have the account, it's fine, dir server will do a pleaseAddCredentials
		strcpy(recvbuf+sizeof(uint16_t), "didnthave");
		bytesSending = writeSendLen(recvbuf, recvbuf+sizeof(uint16_t));
		sendTLS(ssl, recvbuf, bytesSending+sizeof(uint16_t));
	}
	else
	{
		strcpy(recvbuf+sizeof(uint16_t), "blocked");
		bytesSending = writeSendLen(recvbuf, recvbuf+sizeof(uint16_t));
		sendTLS(ssl, recvbuf, bytesSending+sizeof(uint16_t));

		char notifyBuf[1000];

		if(!strcmp(whichCountry, "US"))
			strcpy(notifyBuf, "Your IP address may have been blocked, but the reporting user didn't specify a country.\n\n");
		else if(!strcmp(whichCountry, "IR"))
			strcpy(notifyBuf, "It appears that your IP address has been blocked in Iran.\n\n");
		else if(!strcmp(whichCountry, "CN"))
			strcpy(notifyBuf, "It appears that your IP address has been blocked in China.\n\n");
		else
			sprintf(notifyBuf, "It appears that your IP address has been blocked in %s.\n\n",
					whichCountry);
		strcat(notifyBuf,"If you can get a new IP address, you will be able to go back to serving these\n");
		strcat(notifyBuf,"blocked users as before. Getting a new IP address will not disrupt your Salmon\n");
		strcat(notifyBuf,"server, or any of your regular internet usage.\n\n");
		strcat(notifyBuf,"Instructions for a typical cable modem:\n");
		strcat(notifyBuf,"1) Unplug the power cord and router's ethernet cable from the modem.\n");
		strcat(notifyBuf,"2) Wait for about a minute.\n");
		strcat(notifyBuf,"3) Connect the modem to some other device via ethernet cable.\n");
		strcat(notifyBuf,"4) Power the modem back on, and wait a minute.\n");
		strcat(notifyBuf,"5) Power the modem off, wait a minute, and connect it to the router as it was\n");
		strcat(notifyBuf,"   at the beginning.\n");
		strcat(notifyBuf,"6) Power the modem back on.\n");
		logMajorNotification(notifyBuf);
	}
}

//
// 
// 
// ABOVE: the already-connected, logic-y stuff
// BELOW: the "make the connections happen" and "shutdown" stuff
// 
// 
//

void* connectionThread(void* arg)
{
	int ourSocket = *(int*)arg;
	free(arg);

	ssl_context* ssl = TLSwithDir(&ourSocket);
	if(!ssl)
	{
		net_close(ourSocket);
		logError("Accepted TCP connection, but failed to establish TLS session.");
		return 0;
	}

	//'z' is a placeholder command, since the situation here is "you're the one connecting to me;
	//I didn't have anything I wanted to do." You can think of it as "zzzz I was sleeping"! :)
	authenticateWithDir(ssl, 'z');

	//now the directory server should tell us which command it's doing
	char recvCommand=0;
	recvTLS(ssl, &recvCommand, 1);
	
	if(recvCommand=='p')//ping: the areYouStillThere function on the dir server
		respondAreYouStillThere(ssl);
	else if(recvCommand=='c')//dir server is telling us some new credentials we should allow
	{
		char credBuf[10000];
		memset(credBuf, 0, 10000);
		BOOL credentialsGood = recvCredentialList(ssl, credBuf, 10000);

		if(credentialsGood)
			setAcceptedCredentials(credBuf);
		else
			logError("Directory server gave us a malformed credentials list...");
	}
	else if(recvCommand=='b')//dir server is checking if we've been blocked in some country
		respondBlockCheck(ssl, ourSocket);
	else if(recvCommand=='n')//dir server is sending us some special, human-written announcement
	{
		char* notifyBuf = 0;
		char* endPtr = 0;
		char recvBuf[1500];
		int bytesRecvd;
		int totalBytesRecvd = 0;
		while(totalBytesRecvd < 1024*1024 && (bytesRecvd = recvTLS(ssl, recvBuf, 1500)) > 0)
		{
			int oldTotalRecvd = totalBytesRecvd;
			totalBytesRecvd += bytesRecvd;
			notifyBuf = realloc(notifyBuf, totalBytesRecvd+1);
			endPtr = notifyBuf + oldTotalRecvd;
			memcpy(endPtr, recvBuf, bytesRecvd);
			endPtr[bytesRecvd] = 0;
		}
		logMajorNotification(notifyBuf);
		free(notifyBuf);
	}
	else
	{
		char errBuf[100];
		sprintf(errBuf, "Server sent unknown command: \"%c\"", recvCommand);
		logError(errBuf);
	}
	shutdownWaitTLS(ssl, ourSocket);
}

void acceptConnections()
{
	int acceptedSocket;
	int listenerSocket;

	if(net_bind(&listenerSocket, NULL, 7004) != 0)
		exitError("Couldn't bind+listen port 7004 on any network interface!");

	while(1)
	{
		//I think if accept() actually fails, it's almost always going to be the type where every
		//call is going to immediately return with the same error, so rather than trying again and
		//again and generating a 10GB logError file, just exit.
		if(net_accept(listenerSocket, &acceptedSocket, NULL) != 0)
			exitError("Failed to accept a connection.");

		int* client_fd = (int*) malloc(sizeof(int));
		*client_fd = acceptedSocket;

		pthread_t thread_id;
		pthread_create(&thread_id, NULL, connectionThread, (void*)client_fd);
		pthread_detach(thread_id);
	}
}

//say "going down" right before we exit. UDP to keep it quick.
void gracefulExit(int theSignal)
{
	uninitTLS();
	
	unsigned char* hashIn = 0;
	struct addrinfo* dirServInfo;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	if(getaddrinfo(SERVER_NAME, "3389", &hints, &dirServInfo) != 0)
		goto ExitError;

	struct addrinfo* eachAddr;
	struct sockaddr* theSendAddr = NULL;
	int theSocket = -1;
	for (eachAddr = dirServInfo; eachAddr != NULL; eachAddr = eachAddr->ai_next)
		if ((theSocket = socket(eachAddr->ai_family, eachAddr->ai_socktype, eachAddr->ai_protocol)) >= 0)
		{
			theSendAddr = eachAddr->ai_addr;
			break;
		}

	if (theSocket < 0)
		goto ExitError;


	time_t sse = time(0);
	//NOTE NOTE remember, network order! INCLUDING the time value that goes into the hash.
	uint64_t time64Bits = sse;	
	uint64_t timeNetOrder;
	hton64(&timeNetOrder, time64Bits);
	
	unsigned char sendbuf[sizeof(uint64_t)+20];//sse, then a SHA-1 hash

	//first get how big the buffer for holding the base64 output needs to be
	//(calling base64_encode with destination null writes that value into bufSize)
	size_t bufSize = 0;
	base64_encode(0, &bufSize, gDirServPassword, DIRSERV_PASSWORD_LENGTH);

	//now actually base64 encode it
	hashIn = malloc(bufSize+sizeof(uint64_t));
	base64_encode(hashIn+sizeof(uint64_t), &bufSize, gDirServPassword, DIRSERV_PASSWORD_LENGTH);
	memcpy(hashIn, &timeNetOrder, sizeof(uint64_t));

	//now hash(time64Bits, base64(password))
	sha1(hashIn, bufSize+sizeof(uint64_t), sendbuf+sizeof(uint64_t));


	//send time64Bits, sha1(time64Bits, base64(pw))
	memcpy(sendbuf, &timeNetOrder, sizeof(uint64_t));

	//thanks to our basic anti-DoS logic, 3 isn't any more expensive/annoying for the directory than 1!
	//so, might as well raise the chance of the message not getting through to the 3rd power.
	sendto(theSocket, sendbuf, sizeof(uint64_t)+20, 0, theSendAddr, sizeof(struct sockaddr));
	sendto(theSocket, sendbuf, sizeof(uint64_t)+20, 0, theSendAddr, sizeof(struct sockaddr));
	sendto(theSocket, sendbuf, sizeof(uint64_t)+20, 0, theSendAddr, sizeof(struct sockaddr));
	
	freeaddrinfo(dirServInfo);
	free(hashIn);
	freeStuff();
	exit(0);

ExitError:
	if(hashIn)
		free(hashIn);
	//(the freeStuff() stuff is freed in exitError)
	exitError("Warning: we were unable to notify the directory server that we're going offline.");
}
