/***************************************************************************
                          connectiontobrowser.cpp  -  description
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

#include "connectiontobrowser.h"
#include "logfile.h"
                                                         
//Prepare Header for Server
string ConnectionToBrowser::PrepareHeaderForServer()
{

string header;

#if defined (PARENTPROXY) && defined (PARENTPORT)
string PortString = "";
if ( Port != 80 )
{
PortString = ":" + Port;
}

 header = RequestType + "http://" + Host + PortString + Request + " HTTP/1.0\r\n";
#else
 header = RequestType + Request + " HTTP/1.0\r\n";
#endif

  vector<string>::iterator it;

  for (it = tokens.begin(); it != tokens.end(); ++it)
  {

    //Skip GET POST HEAD line
    if( ( it->find( "GET", 0) == 0) || ( it->find( "POST", 0 ) == 0 ) || ( it->find( "HEAD", 0 ) == 0 ) )
    {
    continue;
    } else if( it->find( "Proxy", 0 ) == 0 )
    {
     continue;
    } else if ( it->find( "Keep-Alive", 0 ) == 0 )
    {
     continue;
    } else if (( it->find( "Accept-Encoding", 0 ) && NOENCODING ) == 0 )
    {
     continue;
    } else if( it->find( "Connection", 0) == 0 )
     {
     continue;
     }

     header += *it;

   }//for


   header += "Connection: close\r\n";
   
   header += "Via: ";
   header += VERSION;
   header += "Havp\r\n";
   
   header += "\r\n";

return header;

}


bool ConnectionToBrowser::AnalyseHeaderLine( string *RequestT ) {

#ifdef TRANSPARENT
  if( RequestT->find( "Host:", 0 ) == 0 )
    {
     return GetHostAndPortOfHostLine( RequestT ); 
    }
#endif
         if( RequestT->find( "GET", 0) == 0)
         {
           RequestType = "GET ";
           return GetHostAndPortOfRequest( RequestT );
         } else if ( RequestT->find( "POST", 0 ) == 0 )
         {
           RequestType="POST ";
           return GetHostAndPortOfRequest( RequestT );
         } else if ( RequestT->find( "HEAD ", 0 ) == 0 )
         {
           RequestType="HEAD ";
           return GetHostAndPortOfRequest( RequestT );
         }

return true;
}


//Get host and port
bool ConnectionToBrowser::GetHostAndPortOfHostLine( string *HostLineT )
{

string::size_type PositionPort;
string PortString;
string HostwithPort;


      HostwithPort = HostLineT->substr(6, HostLineT->length()-6);

       if( ( PositionPort = HostwithPort.rfind( ":", string::npos )) != string::npos )
        {
           Host = HostwithPort.substr(0, PositionPort );
           PortString = HostwithPort.substr( PositionPort+1, HostwithPort.length()-PositionPort );
           if (sscanf( PortString.c_str(), "%d", &Port) != 1){
           return false;
           }
          return true;
        }
       Port = 80;
       Host = HostwithPort;

  return true;
}

bool ConnectionToBrowser::GetHostAndPortOfRequest(string *RequestT )
{

string::size_type Begin;
string::size_type lastposition;

string PortString;

#ifndef TRANSPARENT

string HostwithPort;
string::size_type End;
string::size_type PositionPort;
int Length;

   if  ((Begin = RequestT->find("http://", 0)) == string::npos )
    {
     return false;
    }

   End = RequestT->find("/", Begin+7);

   if ( (End == string::npos ) || ( (Length = End-Begin-7) < 0 ) )
    {
      return false;
    }

   HostwithPort = RequestT->substr(Begin+7, Length);

       if( ( PositionPort = HostwithPort.rfind( ":", string::npos )) != string::npos )
        {
           Host = HostwithPort.substr(0, PositionPort );
           PortString = HostwithPort.substr( PositionPort+1, HostwithPort.length()-PositionPort );
           if (sscanf( PortString.c_str(), "%d", &Port) != 1){
           return false;
           }
        } else {
       Port = 80;
       Host = HostwithPort;
        }

   Request = RequestT->substr(End, RequestT->length()-Begin);
   
#else

   if  ((Begin = RequestT->find("/", 0)) == string::npos )
    {
     return false;
    }
  Request = RequestT->substr(Begin, RequestT->length()-Begin);
         
#endif


   //Get rid of HTTP (1.0)
   if ((Begin = Request.rfind(" HTTP",string::npos)) == string::npos )
   {
     return false;
   }

   Request.replace( Begin, Request.length()-Begin, "" );

   //Delete space or tab at end
   if ( (lastposition = Request.find_last_not_of("\t ")) != string::npos )
   {
     Request = Request.substr(0,lastposition+1);
   }

return true;
}


const char *ConnectionToBrowser::GetHost()
{
  return Host.c_str();
}

const char *ConnectionToBrowser::GetCompleteRequest()
{
  string CompleteRequest = "http://" + Host + Request;
  return CompleteRequest.c_str();
}

int ConnectionToBrowser::GetPort()
{
  return Port;
}

//Constructor
ConnectionToBrowser::ConnectionToBrowser(){

 RequestType="";
  
}

//Destructor
ConnectionToBrowser::~ConnectionToBrowser(){
}
