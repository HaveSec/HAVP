/***************************************************************************
                          sockethandler.cpp  -  description
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

#include "sockethandler.h"
#include "logfile.h"
#include "params.h"
#include "utils.h"

#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) -1)
#endif
#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

//Create Server Socket
bool SocketHandler::CreateServer( int portT, in_addr_t bind_addrT )
{
    int i = 1;

    my_s_addr.sin_addr.s_addr = bind_addrT;
    my_s_addr.sin_port = htons(portT);

    if ( (sock_fd = socket( AF_INET, SOCK_STREAM, 0 )) < 0 )
    {
        LogFile::ErrorMessage("socket() failed: %s\n", strerror(errno));
        return false;
    }

    // Enable re-use Socket
    if ( setsockopt( sock_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i) ) < 0 )
    {
        LogFile::ErrorMessage("setsockopt() failed: %s\n", strerror(errno));
        return false;
    }

    if ( ::bind( sock_fd, (struct sockaddr *) &my_s_addr, sizeof(my_s_addr) ) < 0 )
    {
        LogFile::ErrorMessage("bind() failed: %s\n", strerror(errno));
        return false;
    }

    if ( ::listen( sock_fd, MAXCONNECTIONS ) < 0 )
    {
        LogFile::ErrorMessage("listen() failed: %s\n", strerror(errno));
        return false;
    }

    return true;
}


//Create Server Socket, convert ASCII address representation into binary one
bool SocketHandler::CreateServer( int portT, string bind_addrT )
{
    if ( bind_addrT == "" )
    {
        return CreateServer( portT, INADDR_ANY );
    }
    else
    {
        return CreateServer( portT, inet_addr( Params::GetConfigString("BIND_ADDRESS").c_str() ) );
    } 
}


//Connect to Server
bool SocketHandler::ConnectToServer()
{
    if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
        LogFile::ErrorMessage("ConnectToServer socket() failed: %s\n", strerror(errno));
        return false;
    }

    if ( source_address != "" )
    {
        if ( ::bind(sock_fd, (struct sockaddr *) &l_addr, sizeof(l_addr)) < 0 )
        {
            LogFile::ErrorMessage("ConnectoToServer bind() failed: %s\n", strerror(errno));
            Close();
            return false;
        }
    }

    int flags, ret;

    //Nonblocking connect to get a proper timeout
    while ( (flags = fcntl(sock_fd, F_GETFL, 0)) < 0 )
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("ConnectToServer fcntl() get failed: %s\n", strerror(errno));
        Close();
        return false;
    }
    while ( fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK) < 0 )
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("ConnectToServer fcntl() O_NONBLOCK failed: %s\n", strerror(errno));
        Close();
        return false;
    }

    while ( (ret = ::connect(sock_fd, (struct sockaddr *) &my_s_addr, sizeof(my_s_addr))) < 0 )
    {
        if (errno == EINTR) continue;

        if (errno != EINPROGRESS)
        {
            if (errno != EINVAL) LogFile::ErrorMessage("connect() failed: %s\n", strerror(errno));
            Close();
            return false;
        }

        break;
    }

    if ( ret != 0 )
    {
        FD_ZERO(&checkfd);
        FD_SET(sock_fd,&checkfd);
        wset = checkfd;

        Timeout.tv_sec = CONNTIMEOUT;
        Timeout.tv_usec = 0;

        ret = select_eintr(sock_fd+1, &checkfd, &wset, NULL, &Timeout);

        if ( ret <= 0 )
        {
            Close();
            return false;
        }

        addr_len = sizeof(peer_addr);

        if ( getpeername(sock_fd, (struct sockaddr *) &peer_addr, (socklen_t *) &addr_len) < 0 )
        {
            Close();
            return false;
        }
    }

    while ( fcntl(sock_fd, F_SETFL, flags) < 0 )
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("ConnectToServer fcntl() set failed: %s\n", strerror(errno));
        Close();
        return false;
    }

    return true;
}


bool SocketHandler::ConnectToSocket( string SocketPath, int retry )
{
    strncpy(my_u_addr.sun_path, SocketPath.c_str(), sizeof(my_u_addr.sun_path)-1);

    if ( (sock_fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0 )
    {
        LogFile::ErrorMessage("ConnectToSocket socket() failed: %s\n", strerror(errno));
        return false;
    }

    int tries = 0;
    int ret;

    for(;;)
    {
        while ( (ret = ::connect(sock_fd, (struct sockaddr *) &my_u_addr, sizeof(my_u_addr))) < 0 )
        {
            if (errno == EINTR) continue;

            if (errno != ENOENT) LogFile::ErrorMessage("ConnectToSocket connect() failed: %s\n", strerror(errno));
            break;
        }

        //Success?
        if ( ret == 0 ) return true;

        //All retried?
        if ( ++tries > retry ) break;

        //Try again in one second
        sleep(1);
        continue;
    }

    Close();
    return false;
}


//Accept Client
bool SocketHandler::AcceptClient( SocketHandler *accept_socketT )
{
    addr_len = sizeof(my_s_addr);

    while ((accept_socketT->sock_fd = ::accept(sock_fd, (sockaddr *) &my_s_addr, (socklen_t *) &addr_len)) < 0)
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("accept() failed: %s\n", strerror(errno));

        return false;
    }

    //Save IP to ToBrowser
    accept_socketT->my_s_addr = my_s_addr;    

    return true;
}


//Send String
bool SocketHandler::Send( string *sock_outT )
{
    int total_sent = 0;
    int len = sock_outT->size();
    int ret, buffer_count;

    while (total_sent < len)
    {
        Timeout.tv_sec = SENDTIMEOUT;
        Timeout.tv_usec = 0;
        FD_ZERO(&checkfd);
        FD_SET(sock_fd,&checkfd);

        ret = select_eintr(sock_fd+1, NULL, &checkfd, NULL, &Timeout);

        if (ret <= 0)
        {
            return false;
        }

        while ((buffer_count = ::send(sock_fd, sock_outT->substr(total_sent).c_str(), len - total_sent, 0)) < 0)
        {
            if (errno == EINTR) continue;

            return false;
        }
        if (buffer_count == 0)
        {
            return false;
        }

        total_sent += buffer_count;
    }
        
    return true;
}


//Receive String - Maximal MAXRECV
//sock_del = false : Do not delete Data from Socket
ssize_t SocketHandler::Recv( string *sock_inT, bool sock_delT, int timeout )
{
    char buffer[MAXRECV+1];
    ssize_t buffer_count;
    int ret;

    if ( timeout != -1 )
    {
        Timeout.tv_sec = timeout;
    }
    else
    {
        Timeout.tv_sec = RECVTIMEOUT;
    }
    Timeout.tv_usec = 0;

    FD_ZERO(&checkfd);
    FD_SET(sock_fd,&checkfd);

    ret = select_eintr(sock_fd+1, &checkfd, NULL, NULL, &Timeout);

    if (ret <= 0)
    {
        return -1;
    }

    if (sock_delT == true)
    {
        while ((buffer_count = ::recv(sock_fd, buffer, MAXRECV, 0)) < 0)
        {
            if (errno == EINTR) continue;

            return -1;
        }
    }
    else
    {
        //No delete from socket
        while ((buffer_count = ::recv(sock_fd, buffer, MAXRECV, MSG_PEEK)) < 0)
        {
            if (errno == EINTR) continue;

            return -1;
        }
    }

    if (buffer_count == 0)
    {
        return 0;
    }

    sock_inT->append(buffer, buffer_count);
    return buffer_count;
}


//Receive String of length sock_length
bool SocketHandler::RecvLength( string *sock_inT, ssize_t sock_lengthT )
{
    char buffer[MAXRECV+1];
    ssize_t buffer_count;
    int received = 0;
    int ret;

    while ( received < sock_lengthT )
    {
        Timeout.tv_sec = RECVTIMEOUT;
        Timeout.tv_usec = 0;

        FD_ZERO(&checkfd);
        FD_SET(sock_fd,&checkfd);

        ret = select_eintr(sock_fd+1, &checkfd, NULL, NULL, &Timeout);

        if (ret <= 0) 
        {
            return false;
        }

        while ((buffer_count = ::recv(sock_fd, buffer, sock_lengthT - received, 0)) < 0)
        {
            if (errno == EINTR) continue;

            return false;
        }

        if (buffer_count == 0)
        {
            return false;
        }

        sock_inT->append(buffer, buffer_count);
        received += buffer_count;

    }

    return true;
}


//Wait and get something from socket until separator
bool SocketHandler::GetLine( string *lineT, string separator, int timeout )
{
    *lineT = "";

    string TempLine;
    string::size_type Position;

    do
    {
        if ( Recv( &TempLine, false, timeout ) == false )
        {
            return false;
        }
    }
    while ( (Position = TempLine.find( separator )) == string::npos );

    TempLine = "";

    if ( RecvLength( &TempLine, Position + separator.size() ) == false )
    {
        return false;
    }

    *lineT = TempLine.erase( Position );

    return true;
}


//Set Server Domain and Port for Client
bool SocketHandler::SetDomainAndPort( const string domainT, int portT )
{
    my_s_addr.sin_port = htons(portT);

    if ( domainT == "" ) return false;

    if ( inet_aton( domainT.c_str(), &ip_addr ) != 0 )
    {
        my_s_addr.sin_addr = ip_addr;
        return true;
    }
    else
    {
        if ( (server = gethostbyname( domainT.c_str() )) )
        {
            memcpy(&my_s_addr.sin_addr, server->h_addr_list[0], server->h_length);
            return true;
        }
    }

    return false;
}


bool SocketHandler::CheckForData( int timeout )
{
    int ret;

    Timeout.tv_sec = timeout;
    Timeout.tv_usec = 0;

    FD_ZERO(&checkfd);
    FD_SET(sock_fd,&checkfd);

    ret = select_eintr(sock_fd+1, &checkfd, NULL, NULL, &Timeout);

    if (ret <= 0)
    {
        return false;
    }

    return true;
}


#ifdef SSLTUNNEL
int SocketHandler::CheckForSSLData( int sockBrowser, int sockServer )
{
    fd_set readfd;
    int fds;

    FD_ZERO(&readfd);
    FD_SET(sockBrowser,&readfd);
    FD_SET(sockServer,&readfd);

    if ( sockBrowser > sockServer )
    {
        fds = sockBrowser;
    }
    else
    {
        fds = sockServer;
    }

    Timeout.tv_sec = 20;
    Timeout.tv_usec = 0;

    int ret = select_eintr(fds+1, &readfd, NULL, NULL, &Timeout);

    if (ret <= 0) return 0;

    if (FD_ISSET(sockBrowser,&readfd)) return 1;

    return 2;
}
#endif


void SocketHandler::Close()
{
    //Check that we have a real fd
    if ( sock_fd > -1 )
    {
        while ( ::close(sock_fd) < 0 )
        {
            if (errno == EINTR) continue;
            if (errno == EBADF) break;

            //IO error?
            LogFile::ErrorMessage("close() failed: %s\n", strerror(errno));
        }

        //Mark socket unused
        sock_fd = -1;
    }
}


//Constructor
SocketHandler::SocketHandler()
{
    memset(&my_s_addr, 0, sizeof(my_s_addr));
    my_s_addr.sin_family = AF_INET;

    memset(&my_u_addr, 0, sizeof(my_u_addr));
    my_u_addr.sun_family = AF_LOCAL;

    //No socket exists yet
    sock_fd = -1;

    source_address = Params::GetConfigString("SOURCE_ADDRESS");

    if ( source_address != "" )
    {
        l_addr.sin_family = AF_INET;
        l_addr.sin_port = htons(0);
        l_addr.sin_addr.s_addr = inet_addr( source_address.c_str() );
    }
}


//Destructor
SocketHandler::~SocketHandler()
{
}
