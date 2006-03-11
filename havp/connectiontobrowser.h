/***************************************************************************
                          connectiontobrowser.h  -  description
                             -------------------
    begin                : Sa Feb 12 2005
    copyright            : (C) 2005 by Christian Hilgers
    email                : christian@hilgers.ag
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef CONNECTIONTOBROWSER_H
#define CONNECTIONTOBROWSER_H

#include "default.h"
#include "httphandler.h"

#include <iostream>
#include <algorithm>
#include <string>
#include <map>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std; 

class ConnectionToBrowser : public HTTPHandler  {

private:

#ifdef REWRITE
map <string,string> URLRewrite;
#endif

vector <string> Methods;

string Request;

string Host;

string IP;

int Port;

string CompleteRequest;

string RequestType;

string RequestProtocol;

string FtpUser;

string FtpPass;

long long ContentLength;

bool KeepAlive;

int AnalyseFirstHeaderLine( string *RequestT );

int AnalyseHeaderLine( string *RequestT );

int GetHostAndPortOfRequest( string *RequestT, string::size_type StartPos );

int GetHostAndPortOfHostLine( string *HostLineT );

public:

string PrepareHeaderForServer();

string GetIP();

const string GetHost();

const string GetRequest();

const string GetCompleteRequest();

const string GetRequestProtocol();

const string GetRequestType();

bool KeepItAlive();

long long GetContentLength();

int GetPort();

#ifdef REWRITE
bool RewriteHost();
#endif

void ClearVars();

	ConnectionToBrowser();
	~ConnectionToBrowser();
};

#endif
