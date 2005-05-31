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

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include "sockethandler.h"

//Create Server Socket
bool SocketHandler::CreateServer( int portT, in_addr_t bind_addrT )
{
  int i = 1;

  s_addr.sin_family = AF_INET;
  s_addr.sin_addr.s_addr = bind_addrT;
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

//Create Server Socket, convert ASCII address representation into binary one
bool SocketHandler::CreateServer( int portT, const char *bind_addrT )
{
  return CreateServer( portT, bind_addrT == NULL ? INADDR_ANY : inet_addr( bind_addrT ) );
}

//Accept Client
bool SocketHandler::AcceptClient ( SocketHandler *accept_socketT )
{
  int addr_length = sizeof ( s_addr );
  accept_socketT->sock_fd = ::accept ( sock_fd, ( sockaddr * ) &s_addr, ( socklen_t * ) &addr_length );

  close ( sock_fd );

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
  int rest = MAXRECV;


    if (  sock_lengthT <  rest ){
      rest =  sock_lengthT;
    }

  while ( sock_lengthT > 0 ) {

      buffer_count = ::recv ( sock_fd, buffer, rest, 0 );

    if ( buffer_count <= -1 )
     {
      return false;
     }

    sock_inT->append(buffer, buffer_count);
    sock_lengthT -= buffer_count;

    if (  sock_lengthT <  rest ){
      rest =  sock_lengthT;
    }

  }

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

bool SocketHandler::CheckForData( )
{
 fd_set checkfd;
 struct timeval Timeout;
 Timeout.tv_sec = 0;
 Timeout.tv_usec = 0;
 
  //Enable nonblocking sockets
  fcntl(sock_fd, F_SETFL, O_NONBLOCK);
 
  FD_ZERO(&checkfd);
  FD_SET(sock_fd,&checkfd);

  select( sock_fd+1 ,&checkfd, NULL, NULL, &Timeout);
  
  if (select( sock_fd+1 ,&checkfd, NULL, NULL, &Timeout) == 0){
     //Disable nonblocking sockets
     fcntl(sock_fd, F_SETFL, ~O_NONBLOCK);
    return false;
  }

  //Disable nonblocking sockets
  fcntl(sock_fd, F_SETFL, ~O_NONBLOCK);
        
return true;
}


bool SocketHandler::IsConnectionDropped()
{
char buffer[1];

if( CheckForData() == true)
{
 if ( ::recv ( sock_fd, buffer, 1, MSG_PEEK ) == 0)
 {
  return true;
 } 
}
    
return false;
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
