/***************************************************************************
                          proxyhandler.h  -  description
                             -------------------
    begin                : So Feb 20 2005
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

#ifndef PROXYHANDLER_H
#define PROXYHANDLER_H

#include "default.h"
#include "connectiontobrowser.h"
#include "connectiontohttp.h"
#include "genericscanner.h"
#include "logfile.h"
#include "params.h"

#include <iostream>
#include <string>
#include <deque>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>

using namespace std;


class ProxyHandler {

private:

bool HeaderSend;

bool BrowserDropped;

bool DropBrowser;

bool ScannerUsed;

bool UnlockDone;

bool AnswerDone;

bool ReinitDone;

bool ServerClosed;

bool ServerConnected;

bool DropServer;

int alivecount;

string ConnectedHost;

int ConnectedPort;

ConnectionToBrowser ToBrowser;
ConnectionToHTTP ToServer;

bool ProxyMessage( int CommunicationAnswerT, string Answer );

int CommunicationHTTP( GenericScanner *VirusScannerT, bool ScannerOff );

int CommunicationFTP( GenericScanner *VirusScannerT, bool ScannerOff );

#ifdef SSLTUNNEL
int CommunicationSSL();
#endif

public:

 bool Proxy ( SocketHandler *ProxyServerT, GenericScanner *VirusScannerT );
 
 
	ProxyHandler();
	~ProxyHandler();
};

#endif
