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
#include "scannerhandler.h"

#include <string>

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

string Header;

ConnectionToBrowser ToBrowser;
ConnectionToHTTP ToServer;

bool UseParentProxy;
string ParentHost;
int ParentPort;

int MaxDownloadSize;
int KeepBackTime;
int TricklingTime;
unsigned int TricklingBytes;
int KeepBackBuffer;

int TransferredHeader;
long long TransferredBody;

bool ProxyMessage( int CommunicationAnswerT, string Answer );
int CommunicationHTTP( ScannerHandler &Scanners, bool ScannerOff );
int CommunicationFTP( ScannerHandler &Scanners, bool ScannerOff );

#ifdef SSLTUNNEL
int CommunicationSSL();
#endif

public:

void Proxy( SocketHandler &ProxyServerT, ScannerHandler &Scanners );
 
ProxyHandler();
~ProxyHandler();

};

#endif
