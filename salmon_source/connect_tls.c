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

//NOTE: This library wrapper was developed working from the example
//code published by the PolarSSL developers. Some chunks are probably
//essentially identical. Note that this modified version has had its
//license upgraded from GPLv2 to GPLv3. Here is the original license summary:

/*
 *  SSL client demonstration program
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "polarssl/net.h"
#include "polarssl/debug.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/error.h"
#include "polarssl/certs.h"

#include "constants.h"
#include "connect_tls.h"

#ifndef POLARSSL_CERTS_C
#error PolarSSL doesnt have certificates...
#endif

x509_crt _connect_tls_dirServCert;
entropy_context _connect_tls_entropy;
ctr_drbg_context _connect_tls_ctr_drbg;

void logErrorFromCode(const char* info, int code)
{
	char wholeThing[600];
	char errbuf[300];
	polarssl_strerror(code, errbuf, 300);
	sprintf(wholeThing, "====================\n%s\nError code -0x%x:\n%s\n====================\n",
		   info, -code, errbuf);
	logError(wholeThing);
}

int initTLS()
{
	int ret, len = -1;
	const char *seedExtraData = "salmon_server_wrapper";

	x509_crt_init(&_connect_tls_dirServCert);

	entropy_init(&_connect_tls_entropy);
	if((ret = ctr_drbg_init(&_connect_tls_ctr_drbg, entropy_func, &_connect_tls_entropy,
	                        (const unsigned char *) seedExtraData,
	                        strlen(seedExtraData))) != 0)
	{
		logErrorFromCode("PolarSSL failed to initialize RNG: ctr_drbg_init returned:", ret);
		return ret;
	}

	const char* certPath = "/var/lib/salmon/salmon_dirserv.crt";
	if(access(certPath, R_OK) != -1)
		ret = x509_crt_parse_file(&_connect_tls_dirServCert, certPath);
	else
	{
		logError("The salmon_dirserv.crt certificate file is corrupted or missing from /var/lib/salmon/salmon_dirserv.crt. salmond needs this file to operate. You can download a copy at https://salmon.cs.illinois.edu/salmon_dirserv.crt.");
		return -1;
	}
	if(ret < 0)
	{
		logErrorFromCode("PolarSSL failed to parse the certificate: x509_crt_parse returned:", ret);
		return ret;
	}

	return 0;
}

//theSocket should be a TCP socket already connected to the directory server.
//theSocket is a pointer for the sake of ssl_set_bio, which takes a pointer.
ssl_context* TLSwithDir(int* theSocket)
{
	int ret;
	ssl_context* ssl = (ssl_context*)malloc(sizeof(ssl_context));
	memset(ssl, 0, sizeof(ssl_context));

	if((ret = ssl_init(ssl)) != 0)
	{
		logErrorFromCode("PolarSSL failed to initialize: ssl_init returned:", ret);
		free(ssl);
		return 0;
	}

	ssl_set_endpoint(ssl, SSL_IS_CLIENT);
	ssl_set_authmode(ssl, SSL_VERIFY_REQUIRED);
	ssl_set_ca_chain(ssl, &_connect_tls_dirServCert, NULL, PEER_NAME);
	ssl_set_rng(ssl, ctr_drbg_random, &_connect_tls_ctr_drbg);
	ssl_set_bio(ssl, net_recv, theSocket, net_send, theSocket);

	while((ret = ssl_handshake(ssl)) != 0)
		if(ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			logErrorFromCode(
				"PolarSSL's handshake with directory server failed: ssl_handshake returned:",ret);
			ssl_free(ssl);
			free(ssl);
			return 0;
		}

	if((ret = ssl_get_verify_result(ssl)) != 0)
	{
		char hmmErr[500];
		hmmErr[0] = 0;
		
		if((ret & BADCERT_EXPIRED) != 0)
			strcat(hmmErr, "Certificate presented by directory server has expired.\n");
		if((ret & BADCERT_REVOKED) != 0)
			strcat(hmmErr, "Certificate presented by directory server has been revoked.\n");
		if((ret & BADCERT_CN_MISMATCH) != 0)
		{
			strcat(hmmErr, "CN in certificate presented by directory server does not match (expected CN=");
			strcat(hmmErr, PEER_NAME);
			strcat(hmmErr, ").\n");
		}
		if((ret & BADCERT_NOT_TRUSTED) != 0)
			strcat(hmmErr, "Certificate presented by directory server not in our trusted list.\n");
		
		if((ret & (BADCERT_NOT_TRUSTED | BADCERT_CN_MISMATCH | BADCERT_REVOKED | BADCERT_EXPIRED)) == 0)
			strcpy(hmmErr, "An unknown error occurred during certificate verification.");
		
		logError(hmmErr);
		ssl_free(ssl);
		free(ssl);
		return 0;
	}
	return ssl;
}


int sendTLS(ssl_context* ssl, const char* buf, unsigned int len)
{
	int ret;
	while((ret = ssl_write(ssl, buf, len)) <= 0)
		if(ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			logErrorFromCode("PolarSSL sending failure: ssl_write returned:", ret);
			return ret;
		}
	return ret;
}

int recvTLS(ssl_context* ssl, char* buf, unsigned int len)
{
	int ret;
	memset(buf, 0, len);
	while((ret = ssl_read(ssl, buf, len)) < 0)
		if(ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			if(ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY)
				return 0; //mimic "recv returns 0 on a shutdown TCP connection"
			logErrorFromCode("PolarSSL receiving failure: ssl_read returned:", ret);
			return ret;
		}
	return ret;
}

void shutdownWaitTLS(ssl_context* ssl, int theTCPsocket)
{
	if(ssl==NULL)
	{
		if(theTCPsocket != -1)
			net_close(theTCPsocket);
		return;
	}

	char discard[100];
	ssl_close_notify(ssl);
	
	while(ssl_read(ssl, discard, 100) > 0){}

	if(theTCPsocket != -1)
		net_close(theTCPsocket);
	ssl_free(ssl);
	memset(ssl, 0, sizeof(ssl_context));
	free(ssl);
}


void shutdownTLS(ssl_context* ssl, int theTCPsocket)
{
	if(ssl==NULL)
	{
		if(theTCPsocket != -1)
			net_close(theTCPsocket);
		return;
	}

	ssl_close_notify(ssl);

	if(theTCPsocket != -1)
		net_close(theTCPsocket);
	ssl_free(ssl);
	memset(ssl, 0, sizeof(ssl_context));
	free(ssl);
}

//------------------------------------------------------------------
//ctr_drbg_free(&ctr_drbg)... not in the standard ubuntu package
//Implementation that should never be optimized out by the compiler
static void salmon_polarssl_zeroize( void *v, size_t n )
{volatile unsigned char *p = v; while( n-- ) *p++ = 0;}
void salmon_aes_free( aes_context *ctx )
{
	if( ctx == NULL )
		return;
	salmon_polarssl_zeroize( ctx, sizeof( aes_context ) );
}
void salmon_ctr_drbg_free( ctr_drbg_context *ctx )
{
	if( ctx == NULL )
		return;
	salmon_aes_free( &ctx->aes_ctx );
	salmon_polarssl_zeroize( ctx, sizeof( ctr_drbg_context ) );
}
//------------------------------------------------------------------
void uninitTLS()
{
	x509_crt_free(&_connect_tls_dirServCert);
	salmon_ctr_drbg_free(&_connect_tls_ctr_drbg);	
	entropy_free(&_connect_tls_entropy);
}

