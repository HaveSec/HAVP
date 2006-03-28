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

#include "default.h"
#include "connectiontobrowser.h"
#include "params.h"
#include "utils.h"

#include <arpa/inet.h>

//Prepare Header for Server
string ConnectionToBrowser::PrepareHeaderForServer( bool ScannerOff, bool UseParentProxy )
{

    string PortString = "";

    if ( Port != 80 && Port != 21 )
    {
        char porttemp[21];
        snprintf(porttemp, 20, ":%d", Port);
        PortString = porttemp;
    }

    string header;
    header.reserve(1000);

    if ( UseParentProxy )
    {
        //HTTP
        if ( RequestProtocol == "http" )
        {
            header = RequestType + " http://" + Host + PortString + Request + " HTTP/1.0\r\n";
            CompleteRequest = "http://" + Host + PortString + Request;
        }
        //FTP
        else if ( RequestProtocol == "ftp" )
        {
            string AuthString = "";

            if ( FtpUser != "" )
            {
                SearchReplace( &FtpUser, ":", "%3A" );
                SearchReplace( &FtpUser, "@", "%40" );

                if ( FtpPass != "" )
                {
                    SearchReplace( &FtpPass, ":", "%3A" );
                    SearchReplace( &FtpPass, "@", "%40" );

                    AuthString = FtpUser + ":" + FtpPass + "@";
                }
                else
                {
                    AuthString = FtpUser + "@";
                }
            }

            header = RequestType + " ftp://" + AuthString + Host + PortString + Request + " HTTP/1.0\r\n";
            CompleteRequest = "ftp://" + Host + PortString + Request;
        }
#ifdef SSLTUNNEL
        //CONNECT
        else if ( RequestProtocol == "connect" )
        {
            header = "CONNECT " + Request + " HTTP/1.0\r\n";
            CompleteRequest = "connect://" + Request;
        }
#endif
    }
    else
    {
        header = RequestType + " " + Request + " HTTP/1.0\r\n";
        CompleteRequest = RequestProtocol + "://" + Host + PortString + Request;
    }

    //Strip long URLs
    if (CompleteRequest.length() > 500)
    {
        CompleteRequest = CompleteRequest.substr(0,500);
        CompleteRequest += "...";
    }

    string via = "";

    vector<string>::iterator itvec;

    string it;
    it.reserve(200);

    //Skip first token
    for (itvec = tokens.begin() + 1; itvec != tokens.end(); ++itvec)
    {

        //Uppercase for matching
        it = UpperCase(*itvec);

        if ( it.find( "PROXY", 0 ) == 0 )
        {
            continue;
        }
        else if ( it.find( "KEEP-ALIVE", 0 ) == 0 )
        {
            continue;
        }
        else if (( it.find( "ACCEPT-ENCODING", 0 ) && NOENCODING ) == 0 )
        {
            continue;
        }
        else if ( it.find( "VIA", 0 ) == 0 )
        {
            string line = *itvec;
            string::size_type Position = line.find_first_not_of(" ", 4);
            if ( Position != string::npos )
            {
                via = ", " + line.substr(Position);
            }
            continue;
        }
        else if ( it.find( "CONNECTION", 0 ) == 0 )
        {
            continue;
        }

        if ( (Params::GetConfigBool("RANGE") == false) && (ScannerOff == false) && (StreamAgent == false) )
        {
           if ( it.find( "RANGE:", 0 ) == 0 )
           {
              continue;
           }
           else if ( it.find( "IF-RANGE", 0 ) == 0 )
	   {
              continue;
           }
        }

        header += *itvec + "\r\n";
    }                                             //for

    header += "Via: 1.0 HAVP" + via + "\r\n";

    return header;

}


int ConnectionToBrowser::AnalyseFirstHeaderLine( string *RequestT )
{

    //Uppercase for matching
    string RequestU = UpperCase(*RequestT);

    //Looking for GET, POST, HEAD, CONNECT etc.
    for(unsigned int i=0;i < Methods.size(); i++)
    {
        if( RequestU.find( Methods[i] + " ", 0 ) == 0 )
        {
            RequestType = Methods[i];
            return GetHostAndPortOfRequest( RequestT, Methods[i].size() + 1 );
        }
    }

    return -202;
}


int ConnectionToBrowser::AnalyseHeaderLine( string *RequestT )
{
    //Uppercase for matching
    string RequestU = UpperCase(*RequestT);

    if (RequestU.find("CONTENT-LENGTH: ", 0) == 0)
    {
        if ( RequestU.find_first_not_of("0123456789", 16) != string::npos )
        {
            //Invalid Content-Length
            return 0;
        }

        string LengthToken = RequestT->substr( 16 );

        //Sanity check for invalid huge Content-Length
        if ( LengthToken.length() > 18 ) return 0;

        if ( sscanf(LengthToken.c_str(), "%lld", &ContentLength) != 1 )
        {
            ContentLength = -1;
        }

        return 0;
    }

    if (ProxyConnection == false)
    {
        if (RequestU.find("CONNECTION: KEEP-ALIVE", 0) == 0)
        {
            KeepAlive = true;

            return 0;
        }

        if (RequestU.find("PROXY-CONNECTION: ", 0) == 0)
        {
            ProxyConnection = true;

            if (RequestU.find("KEEP-ALIVE", 18) != string::npos)
            {
                KeepAlive = true;
            }
            else
            {
                KeepAlive = false;
            }

            return 0;
        }
    }

    if (Params::GetConfigBool("FORWARDED_IP") == true)
    {
        if (RequestU.find( "X-FORWARDED-FOR: ", 0 ) == 0)
        {
            IP = RequestT->substr(17);
            return 0;
        }
    }

    if (RequestU.find("USER-AGENT: ", 0) == 0)
    {
        UserAgent = RequestT->substr(12);

        if (Params::GetConfigString("STREAMUSERAGENT") != "")
        {
            vector<string>::iterator UAi;

            for (UAi = StreamUA.begin(); UAi != StreamUA.end(); ++UAi)
            {
                if (RequestU.find(*UAi, 12) != string::npos)
                {
                    StreamAgent = true;
                }
            }
        }

        return 0;
    }

    //Checks for TRANSPARENT
    if (Transparent && RequestU.find( "HOST: ", 0 ) == 0)
    {
        return GetHostAndPortOfHostLine( RequestT );
    }

    return 0;
}


//Get host and port
int ConnectionToBrowser::GetHostAndPortOfHostLine( string *HostLineT )
{

    string HostwithPort = HostLineT->substr( 6 );

    string::size_type PositionPort;

    if ( ( PositionPort = HostwithPort.find( ":", 1 )) != string::npos )
    {
        Host = HostwithPort.substr( 0, PositionPort );

        if ( Host.length() > 67 )
        {
            return -210;
        }

        string PortString = HostwithPort.substr( PositionPort );

        if ( PortString.length() > 6 )
        {
            return -212;
        }

        if ( sscanf(PortString.c_str(), ":%d", &Port) != 1 )
        {
            return -212;
        }

        if ( Port < 1 || Port > 65535 )
        {
            return -212;
        }

        return 0;
    }

    Host = HostwithPort;
    Port = 80;

    return 0;
}


int ConnectionToBrowser::GetHostAndPortOfRequest( string *RequestT, string::size_type StartPos )
{

    string::size_type Begin, LastPosition;

#ifdef SSLTUNNEL
    //Handle SSL
    if (RequestType == "CONNECT")
    {
        RequestProtocol = "connect";

        if ( (Begin = RequestT->find_first_not_of( " ", 8 )) != string::npos )
        {
            if ( (LastPosition = RequestT->find( " ", Begin )) != string::npos )
            {
                string HostwithPort = RequestT->substr( Begin, LastPosition - Begin );

                if ( (Begin = HostwithPort.find( ":", 1 )) != string::npos )
                {
                    Host = HostwithPort.substr( 0, Begin );

                    if (Host.length() > 67)
                    {
                        return -210;
                    }

                    string PortString = HostwithPort.substr( Begin );

                    //Normally only 443 and 563 are allowed ports
                    if ( PortString != ":443" && PortString != ":563" )
                    {
                        return -211;
                    }

                    if ( sscanf(PortString.c_str(), ":%d", &Port) == 1 )
                    {
                        Request = HostwithPort;

                        return 0;
                    }
                }
            }
        }

        return -201;
    }
#endif

    //Check for other protocols..

    //Transparent proxying?
    if ( Params::GetConfigBool("TRANSPARENT") == true )
    {
        if ( RequestT->find( "/", StartPos ) == StartPos )
        {
            if ( (LastPosition = RequestT->find( " ", StartPos )) != string::npos )
            {
                if ( LastPosition > 4096 ) return -201;

                RequestProtocol = "http";
                Request = RequestT->substr( StartPos, LastPosition - StartPos );

                return 0;
            }
        }

        return -201;
    }

    //Uppercase for matching
    string RequestU = UpperCase(*RequestT);

    //HTTP
    if ( (Begin = RequestU.find( "HTTP://", StartPos )) == StartPos )
    {
        RequestProtocol = "http";
        Begin += 7;
    }
    //FTP
    else if ( (Begin = RequestU.find( "FTP://", StartPos )) == StartPos )
    {
        RequestProtocol = "ftp";
        Begin += 6;
    }
    //No supported protocol found
    else
    {
        return -201;
    }

    //Start parsing request..

    if ( (LastPosition = RequestT->find( " ", Begin )) == string::npos )
    {
        return -201;
    }
    if ( LastPosition == Begin || LastPosition > 4096 )
    {
        return -201;
    }

    //Split domain and path
    string RequestDomain = RequestT->substr( Begin, LastPosition - Begin );

    if ( (LastPosition = RequestDomain.find( "/", 0 )) != string::npos )
    {
        Request = RequestDomain.substr( LastPosition );
        RequestDomain = RequestDomain.substr( 0, LastPosition );
    }
    else
    {
        Request = "/";
    }

    //Check for login info
    if ( (LastPosition = RequestDomain.rfind( "@", string::npos )) != string::npos )
    {
        if ( RequestProtocol == "ftp" )
        {
            string UserPass = RequestDomain.substr( Begin, LastPosition + 1 );

            string::size_type Position;

            if ( (Position = UserPass.find( ":", 0 )) != string::npos )
            {
                FtpUser = UserPass.substr( 0, Position );
                FtpPass = UserPass.replace( 0, Position + 1, "" );
            }
            else
            {
                FtpUser = UserPass;
                FtpPass = "";
            }
        }

        //Strip login info.. also from HTTP because IE does it anyway
        RequestDomain.replace( 0, LastPosition + 1, "" );
        RequestT->replace( Begin, LastPosition + 1, "" );

        if ( !RequestDomain.length() )
        {
            return -201;
        }
    }

    //Check for Port and Host
    if ( (LastPosition = RequestDomain.rfind( ":", string::npos )) != string::npos )
    {
        string PortString = RequestDomain.substr( LastPosition );

        if ( PortString.length() > 6 )
        {
            return -212;
        }

        if ( sscanf(PortString.c_str(), ":%d", &Port) != 1 )
        {
            return -212;
        }

        if ( Port < 1 || Port > 65535 )
        {
            return -212;
        }

        Host = RequestDomain.substr( 0, LastPosition );
    }
    else
    {
        if ( RequestProtocol == "http" )
        {
            Port = 80;
        }
        else if ( RequestProtocol == "ftp" )
        {
            Port = 21;
        }
        else
        {
            return -215;
        }

        Host = RequestDomain;
    }

    //Sanity check - TODO: Config variable for allowed ports?
    if ( Host.length() > 73 )
    {
        return -210;
    }
    //if ( RequestProtocol == "http" && Port < 80 )
    //{
    //    return -211;
    //}

    return 0;
}


const string ConnectionToBrowser::GetHost()
{
    return Host;
}

const string ConnectionToBrowser::GetRequest()
{
    return Request;
}

const string ConnectionToBrowser::GetCompleteRequest()
{
    return CompleteRequest;
}

const string ConnectionToBrowser::GetRequestProtocol()
{
    return RequestProtocol;
}

const string ConnectionToBrowser::GetRequestType()
{
    return RequestType;
}

const string ConnectionToBrowser::GetUserAgent()
{
    return UserAgent;
}

long long ConnectionToBrowser::GetContentLength()
{
    return ContentLength;
}

int ConnectionToBrowser::GetPort()
{
    return Port;
}

string ConnectionToBrowser::GetIP()
{
   if (IP == "")
   {
       IP = inet_ntoa( my_s_addr.sin_addr );
   }

   //Else IP was set by X-Forwarded-For:
   return IP;
}

bool ConnectionToBrowser::KeepItAlive()
{
    return KeepAlive;
}


bool ConnectionToBrowser::StreamingAgent()
{
    return StreamAgent;
}

#ifdef REWRITE
bool ConnectionToBrowser::RewriteHost()
{
    if(URLRewrite[Host] != "" )
    {
        Host = URLRewrite[Host];
        return true;
    }

    return false;
}
#endif

void ConnectionToBrowser::ClearVars()
{
    RequestProtocol = RequestType = Request = Host = IP = FtpUser = FtpPass = UserAgent = "";
    Port = ContentLength = -1;
    KeepAlive = ProxyConnection = StreamAgent = false;
}


//Constructor
ConnectionToBrowser::ConnectionToBrowser()
{

#ifdef REWRITE
    REWRITE
#endif

    string TempMethods[] = {METHODS};

    for(unsigned int i = 0; i < sizeof(TempMethods)/sizeof(string); i++)
    {
        Methods.push_back( TempMethods[i] );
    }

    if (Params::GetConfigString("STREAMUSERAGENT") != "")
    {
        string Tokens = UpperCase(Params::GetConfigString("STREAMUSERAGENT"));
        string::size_type Position;
        
        while ((Position = Tokens.find(" ")) != string::npos)
        {
            if (Position == 0)
            {
                Tokens.erase(0, 1);
                continue;
            }
                                    
            StreamUA.push_back(Tokens.substr(0, Position));
            Tokens.erase(0, Position + 1);
        }

        StreamUA.push_back(Tokens);
    }

    Transparent = Params::GetConfigBool("TRANSPARENT");
}


//Destructor
ConnectionToBrowser::~ConnectionToBrowser()
{
}
