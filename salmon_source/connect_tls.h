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

#ifndef __SALMON_CONNECTTLS_INCLGUARD_
#define __SALMON_CONNECTTLS_INCLGUARD_

#include "polarssl/ssl.h"

int initTLS();
ssl_context* TLSwithDir(int* theSocket);
int sendTLS(ssl_context* ssl, const char* buf, unsigned int len);
int recvTLS(ssl_context* ssl, char* buf, unsigned int len);
void shutdownWaitTLS(ssl_context* ssl, int theTCPsocket);
void shutdownTLS(ssl_context* ssl, int theTCPsocket);
void uninitTLS();

#endif
