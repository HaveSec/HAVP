/***************************************************************************
                          sockethandler.h  -  description
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

#ifndef SOCKETHANDLER_H
#define SOCKETHANDLER_H

#include "default.h"

#include <netinet/in.h>
#include <netdb.h>

#include <iostream>

using namespace std;

class SocketHandler {

private:

int port;
int sock_fd;
struct sockaddr_in s_addr;
  
public:

bool CreateServer( int portT );

bool AcceptClient ( SocketHandler *accept_socketT );

bool ConnectToServer ( );

int Send ( string *sock_outT );

ssize_t Recv ( string *sock_inT , bool sock_delT);

bool RecvLength ( string *sock_inT, ssize_t sock_lengthT );

bool SetDomainAndPort(const char *domainT, int portT);

bool CheckForData();

int Close();

	SocketHandler();
	~SocketHandler();
};

#endif
