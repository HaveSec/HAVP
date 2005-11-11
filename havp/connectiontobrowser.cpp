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

//Prepare Header for Server
string ConnectionToBrowser::PrepareHeaderForServer()
{

    string header;
    bool found= false;

    // #if defined (PARENTPROXY) && defined (PARENTPORT)
    string parentproxy=Params::GetConfigString("PARENTPROXY");
    int parentport=Params::GetConfigInt("PARENTPORT");
    if( parentproxy != "" && parentport != 0 ) {
    string PortString = "";
    if ( Port != 80 )
    {
        char PortTemp[21];
        snprintf(PortTemp, 20, ":%d", Port);
        PortString = PortTemp;
    }

    header = RequestType + "http://" + Host + PortString + Request + " HTTP/1.0\r\n";
    // #else
    } else {
    header = RequestType + Request + " HTTP/1.0\r\n";
    }
    // #endif

    vector<string>::iterator it;

    for (it = tokens.begin(); it != tokens.end(); ++it)
    {
        found = false;

        //Skip GET POST HEAD ... Methods line
        for(unsigned int i=0;i < Methods.size(); i++)
        {
            if(  it->find( Methods[i], 0) == 0)
            {
                found = true;
                break;
            }
        }

        if( found == true )
        {
            continue;
        }
        else if( it->find( "Proxy", 0 ) == 0 )
        {
            continue;
        } else if ( it->find( "Keep-Alive", 0 ) == 0 )
        {
            continue;
        } else if (( it->find( "Accept-Encoding", 0 ) && NOENCODING ) == 0 )
        {
            continue;
        } else if ( it->find( "Via", 0 ) == 0 )
        {
            continue;
        } else if( it->find( "Connection", 0) == 0 )
        {
            continue;
        }

        header += *it;

    }                                             //for

    header += "Connection: close\r\n";

    header += "Via: ";
    header += VERSION;
    header += " Havp\r\n";

    header += "\r\n";

    return header;

}


bool ConnectionToBrowser::AnalyseHeaderLine( string *RequestT )
{

    if(Params::GetConfigBool("TRANSPARENT")) {
      if( RequestT->find( "Host:", 0 ) == 0 )
      {
        return GetHostAndPortOfHostLine( RequestT );
      }
    }

    if (Params::GetConfigBool("FORWARDED_IP") )
    {
      if ( RequestT->find( "X-Forwarded-For: ", 0 ) == 0 )
      {
        IP = RequestT->substr( 17, RequestT->length()-17 );
        return true;
      }
    }

    //Looking for GET, POST, HEAD
    for(unsigned int i=0;i < Methods.size(); i++)
    {
        if(  RequestT->find( Methods[i], 0) == 0)
        {
            RequestType = Methods[i] + " ";
            return GetHostAndPortOfRequest( RequestT );
        }
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
        if (sscanf( PortString.c_str(), "%d", &Port) != 1)
        {
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

    // #ifndef TRANSPARENT
    if(! Params::GetConfigBool("TRANSPARENT")) {

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
        if (sscanf( PortString.c_str(), "%d", &Port) != 1)
        {
            return false;
        }
    }
    else
    {
        Port = 80;
        Host = HostwithPort;
    }

    Request = RequestT->substr(End, RequestT->length()-Begin);

    // #else
    } else {

    if  ((Begin = RequestT->find("/", 0)) == string::npos )
    {
        return false;
    }
    Request = RequestT->substr(Begin, RequestT->length()-Begin);
    // #endif
    }

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
    if ( Host == "" ){
      return NULL;
    }

    return Host.c_str();
}

const string ConnectionToBrowser::GetRequest()
{
    return Request;
}


const char *ConnectionToBrowser::GetCompleteRequest()
{
    string CompleteRequest = "http://" + Host + Request;
    return CompleteRequest.c_str();
}


const string ConnectionToBrowser::GetRequestType()
{
    return RequestType;
}


int ConnectionToBrowser::GetPort()
{
    return Port;
}


string ConnectionToBrowser::GetIP ()
{

   if (IP == "") {
     IP = inet_ntoa( s_addr.sin_addr );
   }
   //else IP was set by X-Forwarded-For:

   return IP;
}

bool ConnectionToBrowser::RewriteHost()
{

    if(URLRewrite[Host] != "" )
    {
      Host = URLRewrite[Host];
      return true;
    }
return false;
}

void ConnectionToBrowser::ClearVars()
{
    RequestType = "";
    Request = "";
    Host = "";
    Port = 0;
    IP = "";
}

//Constructor
ConnectionToBrowser::ConnectionToBrowser()
{

#ifdef REWRITE
REWRITE
#endif

    string TempMethods[] =  {METHODS};

    for(unsigned int i = 0; i < sizeof(TempMethods)/sizeof(string); i++)
    {
        Methods.push_back( TempMethods[i] );
    }

    RequestType="";

}


//Destructor
ConnectionToBrowser::~ConnectionToBrowser()
{
}
