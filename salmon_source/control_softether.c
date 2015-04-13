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
#include <string.h>
#include <pthread.h>

#include "constants.h"
#include "globals.h"

#include "stringLL.h"
#include "control_softether.h"


void ensurePortBlocks(char* hubName);

void ensureHub(char* hubName)
{
	//if this is the first time this function has been called, the "hubName" hub won't exist.
	//if that's the case, then create it now.
	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /password:%s /cmd hublist", gAdminPass);
	FILE* hubLister = popen(toExec, "r");
	if(!hubLister)
	{
		logError("Could not run hublist on SoftEther.");
		return;
	}

	BOOL hubExists = FALSE;

	size_t lineGetterLen = 200;
	char* lineGetter = malloc(lineGetterLen);
	memset(lineGetter, 0, lineGetterLen);
	while(getline(&lineGetter, &lineGetterLen, hubLister) > 0)
	{
		if(strstr(lineGetter, hubName) && strstr(lineGetter, "Virtual Hub Name"))
		{
			hubExists = TRUE;
			break;
		}
	}
	pclose(hubLister);
	free(lineGetter);


	if(!hubExists)
	{
		sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /password:%s /cmd hubcreate %s /password:%s",
					gAdminPass, hubName, gAdminPass);
		system(toExec);
		//it looks like vpncmd might return before the change is fully "in effect" in
		//the actual server process... this sleep ought to fix the "could not userlist" error.
		//(as well as ensure that the next two commands will be applied to a hub that exists.)
		sleep(2);
	}
	
	//ensures access control rules (only http(s) etc are allowed) have been applied; applies if not
	ensurePortBlocks(hubName);

	//regardless of whether the hub needed to be created, ensure [chosen NAT method] and DHCP server are on.
	//NOTE the apparent async nature of vpncmd makes me nervous; i'd rather not rely on the sleep(2) up there.
	//just doing this every time seems safest. they're all simple idempotent "set to this value" ops anyways.
	if(gUseSoftEtherSecureNAT)
	{
		sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd:securenatenable",
					hubName, gAdminPass);
		system(toExec);
		sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd:dhcpenable",
					hubName, gAdminPass);
		system(toExec);
		sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd:dhcpset /START:%s.2 /END:%s.254 /MASK:255.255.255.0 /EXPIRE:7200 /GW:%s.1 /DNS:8.8.8.8 /DNS2:none /DOMAIN:none /LOG:yes",
					hubName, gAdminPass, gTapBaseIP, gTapBaseIP, gTapBaseIP);
		system(toExec);
	}
	else
	{
		sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd:securenatenable",
					hubName, gAdminPass);
		system(toExec);
		sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd:natdisable",
					hubName, gAdminPass);
		system(toExec);
		sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd:dhcpenable",
					hubName, gAdminPass);
		system(toExec);
		sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd:dhcpset /START:%s.2 /END:%s.254 /MASK:255.255.255.0 /EXPIRE:7200 /GW:%s.1 /DNS:8.8.8.8 /DNS2:none /DOMAIN:none /LOG:yes",
					hubName, gAdminPass, gTapBaseIP, gTapBaseIP, gTapBaseIP);
		system(toExec);
	}
}


StringLL* getExistingUsers()
{
	BOOL anyoneThere = FALSE;
	StringLL* existingUsersHead = newStringLL();
	StringLL* curExistTail = existingUsersHead;
	curExistTail->next = 0;

	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:salmon /password:%s /cmd userlist",  gAdminPass);
	FILE* userLister = popen(toExec, "r");
	if(!userLister)
	{
		logError("Could not run userlist on SoftEther.");
		return 0;
	}

	size_t lineGetterLen = 200;
	char* lineGetter = malloc(lineGetterLen);
	memset(lineGetter, 0, lineGetterLen);
	while(getline(&lineGetter, &lineGetterLen, userLister) > 0)
		if(strstr(lineGetter, "User Name") && strchr(lineGetter, '|'))
		{
			anyoneThere = TRUE;
			//format: User Name      ...       |theusername
			char* nameStart = strchr(lineGetter, '|')+1;
			if(strchr(nameStart, '\n'))
				*strchr(nameStart, '\n') = 0;
			curExistTail = StringLL_add(curExistTail, nameStart);
		}
	
	pclose(userLister);
	free(lineGetter);

	if(!anyoneThere)
	{
		StringLL_free(existingUsersHead);
		return 0;
	}

	return existingUsersHead;
}

void setAcceptedCredentials(const char* credBuf)
{
	//NOTE max email address length is 254, so this should be enough
	char toExec[EXEC_VPNCMD_BUFSIZE];
	StringLL* newUsersHead = newStringLL();
	StringLL* newPassHead = newStringLL();
	StringLL* curUsersTail = newUsersHead;
	StringLL* curPassTail = newPassHead;
	
	char* credBufCopy = strdup(credBuf);//don't strtok an unfamiliar string, it could be a constant!
	
	//construct our received list of user credentials from the raw string
	char* cUsr = strtok(credBufCopy, "\n");
	if(!cUsr)
	{
		StringLL_free(newUsersHead);
		StringLL_free(newPassHead);
		free(credBufCopy);
		return;
	}
	char* cP = strtok(0, "\n");
	if(!cP)
	{
		StringLL_free(newUsersHead);
		StringLL_free(newPassHead);
		free(credBufCopy);
		return;//minor error
	}
	//NOTE: 	we could be interpreting the above cases (no identities listed) as meaning "wipe out
	//		everyone". however, in case there was just some hiccup, i wouldn't want to mess things
	//		up like that. so, if we really did want to tell a server to revoke everyone's access,
	//		we will instead just send them a single dummy account here.

	while(cUsr && cP)
	{
		curUsersTail = StringLL_add(curUsersTail, cUsr);
		curPassTail = StringLL_add(curPassTail, cP);
		cUsr = strtok(0, "\n");
		cP = strtok(0, "\n");
	}

	//the first time this function is ever called, hub "salmon" won't exist. in that case, create it now.
	//(ensureHub also ensures that DHCP is on, and configures whichever NAT is being used.)
	ensureHub("salmon");
	
	//regardless of whether the hub needed to be created, ensure that softether's ipsec setting is on.
	//NOTE: ipsecenable is server-wide, so don't specify a hub!
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /password:%s /cmd:ipsecenable /L2TP:yes /L2TPRAW:no /ETHERIP:no /PSK:%s /DEFAULTHUB:salmon", gAdminPass, gMyPSK);
	system(toExec);

	//get the list of users we currently accept.
	StringLL* existingUsersHead = getExistingUsers();
	//NOTE: don't need to check for null; it would return null if no one exists, and that's fine.
	
	curUsersTail->next = 0;
	curPassTail->next = 0;

	//now, check if any users in our newly received list aren't already configured to be accepted: add them.
	StringLL* curUsers = newUsersHead;
	StringLL* curPass = newPassHead;
	StringLL* curExist;
	while(curUsers && curUsers->str)
	{
		if(!StringLL_contains(existingUsersHead, curUsers->str))
		{
			sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:salmon /password:%s /cmd usercreate %s /group:none /realname:none /note:none", gAdminPass, curUsers->str);
			system(toExec);
			///Again, softether's async nature is a problem here... in some (not all) test runs, the
			//client fails to connect until you manually set the pw on both the server and client - 
			//I'm pretty sure that system() returns before usercreate "takes effect", and then
			//userpasswordset fails (no user to set). (The crazy scrambled username is the same on both;
			//the pw gets derived in the same way, so there's no way it's a problem with that). 
			//Considering that even with no separation between them it was working more often than not, 
			//just sleep(1) alone would probably be ok, but let's do it the truly correct way.
			StringLL* checkForNewUser = 0;
			while(!StringLL_contains((checkForNewUser = getExistingUsers()), curUsers->str))
			{
				sleep(1);
				StringLL_free(checkForNewUser);
			}
			StringLL_free(checkForNewUser);
			
			sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:salmon /password:%s /cmd userpasswordset %s /password:%s", gAdminPass, curUsers->str, curPass->str);
			system(toExec);
		}

		curUsers = curUsers->next;
		curPass = curPass->next;
	}

	//finally, check if any currently accepted users aren't mentioned in the received list: remove them.
	curExist = existingUsersHead;
	while(curExist && curExist->str)
	{
		if(!StringLL_contains(newUsersHead, curExist->str))
		{
			sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:salmon /password:%s /cmd userdelete %s", gAdminPass, curExist->str);
			system(toExec);
		}

		curExist = curExist->next;
	}

	//at this point, the first two are guaranteed to have been allocated, and ok to freeStringLL on.
	//however, existingUsersHead will be null if there weren't any users at the start of the functions,
	//but there WERE some we were asked to add.
	StringLL_free(newUsersHead);
	StringLL_free(newPassHead);
	if(existingUsersHead)
		StringLL_free(existingUsersHead);
	free(credBufCopy);
}


//verify that userAccount is an account in our softether salmon hub
BOOL verifyUserAccount(const char* userAccount)
{
	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:salmon /password:%s /cmd userlist",
		   gAdminPass);
	FILE* userLister = popen(toExec, "r");
	if(!userLister)
	{
		logError("Could not run userlist on the 'salmon' hub of SoftEther.");
		return FALSE;
	}
	size_t lineGetterLen = 200;
	char* lineGetter = malloc(lineGetterLen);
	memset(lineGetter, 0, lineGetterLen);
	BOOL accountIsThere = FALSE;
	while(getline(&lineGetter, &lineGetterLen, userLister) > 0)
	{
		if(strstr(lineGetter, userAccount))
		{
			accountIsThere = TRUE;
			break;
		}
	}
	pclose(userLister);
	free(lineGetter);
	
	return accountIsThere;
}










//ensures access control rules (only http(s) etc are allowed) have been applied; applies if not
void ensurePortBlocks(char* hubName)
{
	char toExec[EXEC_VPNCMD_BUFSIZE];
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accesslist",
		   hubName, gAdminPass);
	FILE* accessLister = popen(toExec, "r");
	if(!accessLister)
	{
		logError("Could not run accesslist on SoftEther.");
		return;
	}

	size_t lineGetterLen = 200;
	char* lineGetter = malloc(lineGetterLen);
	memset(lineGetter, 0, lineGetterLen);
	while(getline(&lineGetter, &lineGetterLen, accessLister) > 0)
	{
		if(strstr(lineGetter, "zzzsalmondefaultdropzzz"))
		{
			pclose(accessLister);
			free(lineGetter);
			return;
		}
	}
	pclose(accessLister);
	free(lineGetter);
	
	
	//
	//If we reach here, the zzzsalmondefaultdropzzz rule isn't present; we assume they all need to be added.
	//
	
	
	//NOTE Lower number = higher priority. I have set HTTP(S) and DNS to be higher priority than the
	//rest: having the most popular rules at the top of the list ought to be more efficient.
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:dns /priority:1 /srcip:%s.0/24 /protocol:0 /destport:53 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:http /priority:1 /srcip:%s.0/24 /protocol:tcp /destport:80 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:https /priority:1 /srcip:%s.0/24 /protocol:tcp /destport:443 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	sleep(1); //softether vpncmd appears to be finnicky about adding so many rules at once
	
	
	
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:ftpssh /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:20-22 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:kerberos /priority:2 /srcip:%s.0/24 /protocol:0 /destport:88 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	sleep(1); //softether vpncmd appears to be finnicky about adding so many rules at once
	
	
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:viber /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:5242 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:viber /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:4244 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:viber /priority:2 /srcip:%s.0/24 /protocol:udp /destport:5243 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	sleep(1); //softether vpncmd appears to be finnicky about adding so many rules at once
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:viber /priority:2 /srcip:%s.0/24 /protocol:udp /destport:9785 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:yahoomessenger /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:5050 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:aim /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:5190 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	sleep(1); //softether vpncmd appears to be finnicky about adding so many rules at once
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:xmpp /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:5222-5223 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:httpalt /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:8008 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd pass /memo:httpalt /priority:2 /srcip:%s.0/24 /protocol:tcp /destport:8080 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /srcport: /tcpstate:",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
	sleep(2); //softether vpncmd appears to be finnicky about adding so many rules at once
	
	
	
	
	sprintf(toExec, "/usr/local/vpnserver/vpncmd /server localhost /hub:%s /password:%s /cmd accessadd discard /memo:zzzsalmondefaultdropzzz /priority:3 /srcip:%s.0/24 /srcusername: /destusername: /srcmac: /destmac: /destip:0.0.0.0/0 /destport: /srcport: /tcpstate: /protocol:0",
				hubName, gAdminPass, gTapBaseIP);
	system(toExec);
}
