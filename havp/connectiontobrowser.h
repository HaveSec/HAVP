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

#include <map>

using namespace std; 

class ConnectionToBrowser : public HTTPHandler  {

private:

string Request;
string Host;
int Port;
string IP;
string CompleteRequest;
string RequestType;
string RequestProtocol;
string FtpUser;
string FtpPass;
string UserAgent;
long long ContentLength;
bool KeepAlive;
bool StreamAgent;
vector<string> Methods;
vector<string> StreamUA;

bool Transparent;

int AnalyseFirstHeaderLine( string *RequestT );
int AnalyseHeaderLine( string *RequestT );
int GetHostAndPortOfRequest( string *RequestT, string::size_type StartPos );
int GetHostAndPortOfHostLine( string *HostLineT );

#ifdef REWRITE
map <string,string> URLRewrite;
#endif

public:

string PrepareHeaderForServer( bool ScannerOff, bool UseParentProxy );
string GetIP();
const string GetHost();
const string GetRequest();
const string GetCompleteRequest();
const string GetRequestProtocol();
const string GetRequestType();
const string GetUserAgent();
bool KeepItAlive();
bool StreamingAgent();
long long GetContentLength();
int GetPort();
void ClearVars();

#ifdef REWRITE
bool RewriteHost();
#endif

ConnectionToBrowser();
~ConnectionToBrowser();

};

#endif
