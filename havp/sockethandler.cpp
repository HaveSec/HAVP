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
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

//Create Server Socket
bool SocketHandler::CreateServer( int portT )
{
  int i = 1;

  s_addr.sin_family = AF_INET;
  s_addr.sin_addr.s_addr = INADDR_ANY;
  s_addr.sin_port = htons ( portT );

  sock_fd = socket ( AF_INET, SOCK_STREAM, 0 );
    if ( sock_fd == -1 )
    return false;

  // Enable re-use Socket
  if ( setsockopt ( sock_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof (i) ) == -1 )
    return false;


  if ( ::bind ( sock_fd, (struct sockaddr *) &s_addr, sizeof ( s_addr ) ) == -1 )
    return false;


  if ( ::listen ( sock_fd, MAXCONNECTIONS ) == -1)
   return false;

  return true;
}

//Accept Client
bool SocketHandler::AcceptClient ( SocketHandler *accept_socketT )
{
  int addr_length = sizeof ( s_addr );
  accept_socketT->sock_fd = ::accept ( sock_fd, ( sockaddr * ) &s_addr, ( socklen_t * ) &addr_length );

  if ( accept_socketT->sock_fd == -1 )
    return false;
  else
    return true;
}


//Connect to Server
bool SocketHandler::ConnectToServer (  )
{

    s_addr.sin_family = AF_INET;

    if ( (sock_fd = socket(s_addr.sin_family, SOCK_STREAM, 0)) == -1 )
		  return false;


    if ( ::connect(sock_fd, (struct sockaddr *) &s_addr, sizeof( s_addr ) ) == -1)
     return false;

	return true;
}

//Send String
int SocketHandler::Send ( string *sock_outT )
{

ssize_t buffer_count;

   buffer_count = ::send ( sock_fd, sock_outT->c_str(), sock_outT->size(), MSG_NOSIGNAL );

   if ( buffer_count == -1 ) {
      return -1;
     }

   return buffer_count;
}

//Receive String - Maximal MAXRECV
//sock_del = false : Do not delete Data from Socket
ssize_t SocketHandler::Recv ( string *sock_inT , bool sock_delT)
{

  char buffer [ MAXRECV + 1 ];
  ssize_t buffer_count;

  if ( sock_delT == true )
  {
  buffer_count = ::recv ( sock_fd, buffer, MAXRECV, 0 );
  } else {
  buffer_count = ::recv ( sock_fd, buffer, MAXRECV, MSG_PEEK ); //No delete from socket
  }

  if ( buffer_count <= -1 )
    {
      return -1;
    }
  else if ( buffer_count == 0 )
    {
      return 0;
    }
  else
    {
	sock_inT->append(buffer, buffer_count);
	return buffer_count;
    }
}


//Receive String of length  sock_length
bool SocketHandler::RecvLength ( string *sock_inT , ssize_t sock_lengthT )
{

  char buffer [ MAXRECV + 1 ];
  ssize_t buffer_count;
  ssize_t buffer_length = 0;
  ssize_t repeat;

  repeat =  int (sock_lengthT / MAXRECV);

  for(int i=0; i <= repeat; i++){

    if ( i == repeat ) {
      int rest = sock_lengthT - ( MAXRECV * repeat);
      buffer_count = ::recv ( sock_fd, buffer, rest, 0 );
    } else {
      buffer_count = ::recv ( sock_fd, buffer, MAXRECV, 0 );
    }

  if ( buffer_count <= -1 )
    {
      return false;
    }
  sock_inT->append(buffer, buffer_count);
  buffer_length = buffer_length + buffer_count;
  }

  if ( buffer_length != sock_lengthT )
      return false;

	return true;

}


//Set Server Domain and Port for Client
bool SocketHandler::SetDomainAndPort(const char *domainT, int portT)
{
	struct hostent* result;

  s_addr.sin_port = htons( portT );
  
 if ((domainT == NULL) || (*domainT == '\0'))
    return false;

	result = gethostbyname(domainT);
	if (result) {
		memcpy(&s_addr.sin_addr, result->h_addr_list[0], result->h_length);
		return true;
	} else {
		return false;
    }
}


int SocketHandler::Close()
{
  ::close(sock_fd);
  return 1;
}

//Constructor
SocketHandler::SocketHandler(){
   memset ( &s_addr,  0,  sizeof ( s_addr ) );
}

//Destructor
SocketHandler::~SocketHandler(){
}
