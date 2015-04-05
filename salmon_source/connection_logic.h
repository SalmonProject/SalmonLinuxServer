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

#ifndef __SALMOND_CONNECTION_LOGIC_INCLGUARD_
#define __SALMOND_CONNECTION_LOGIC_INCLGUARD_

#include <sys/socket.h>

char authenticateWithDir(ssl_context* ssl, char command);
void* connectionThread(void* arg);
void gracefulExit(int theSignal);
void acceptConnections();
BOOL serverUp(ssl_context* ssl);
BOOL registerSelf(ssl_context* ssl);
BOOL recvCredentialList(ssl_context* ssl, char* theBuf, unsigned int maxBufLen);

#define SERVER_PORT 8080
#define SERVER_NAME "salmon.cs.illinois.edu"

#endif
