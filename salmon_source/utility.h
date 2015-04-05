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

#ifndef _SALMON_INCL_GUARD__UTILITY_H__
#define _SALMON_INCL_GUARD__UTILITY_H__

void daemonize();
uint16_t writeSendLen(char* dest, char* strlenOfThis);
void logMajorNotification(const char* theString);
void logMajorError(const char* theString);
void logError(const char* theString);
void genPassword();
int readPWPSK();
void ensureCertFile();
void loadSettings();
void wipePassword();
void hton64(uint64_t* output, uint64_t input);
void freeStuff();

#endif
