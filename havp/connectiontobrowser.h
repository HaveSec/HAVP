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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <algorithm>
#include <string>

#include <stdarg.h>
#include <stdio.h>

using namespace std; 

#include "httphandler.h"


class ConnectionToBrowser : public HTTPHandler  {

private:

string Request;

string Host;

int Port;


string RequestType;

bool AnalyseHeaderLine( string *RequestT );

bool GetHostAndPortOfRequest(string *RequestT);

bool GetHostAndPortOfHostLine( string *HostLineT );

public:

string PrepareHeaderForServer();

const char *GetHost();

const char *GetCompleteRequest();

int GetPort();

      
	ConnectionToBrowser();
	~ConnectionToBrowser();
};

#endif
