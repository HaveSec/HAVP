/***************************************************************************
                          connectiontohttp.cpp  -  description
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

#include "connectiontohttp.h"
#include "logfile.h"
#include "utils.h"

#include <stdio.h>

extern int LL; //LogLevel

//Prepare Header for Browser
string ConnectionToHTTP::PrepareHeaderForBrowser()
{
    string header;
    header.reserve(20000);
    header = "";

    vector<string>::iterator itvec;

    string it;
    it.reserve(200);

    //Strip unwanted headers to browser
    for (itvec = tokens.begin(); itvec != tokens.end(); ++itvec)
    {
        //Uppercase for matching
        it = UpperCase(*itvec);

        if ( MatchBegin( it, "KEEP-ALIVE", 10 ) )
        {
            continue;
        }
        else if ( MatchBegin( it, "CONNECTION", 10 ) )
        {
            continue;
        }
        else if ( MatchBegin( it, "PROXY-CONNECTION", 16 ) )
        {
            continue;
        }
        else if ( MatchBegin( it, "CONTENT-LENGTH", 14 ) && (ContentLength == -1) )
        {
            //Do not pass invalid Content-Length
            continue;
        }
        else if ( MatchBegin( it, "TRANSFER-ENCODING", 17 ) )
        {
            continue;
        }

        header += *itvec;
        header += "\r\n";
    }

    return header;

}


int ConnectionToHTTP::AnalyseFirstHeaderLine( string &RequestT )
{

    string::size_type Space;

    if ( (Space = RequestT.find( " ", 0 )) > 0 )
    {
        string::size_type DigitPos;

        if ( (DigitPos = RequestT.find_first_of( "0123456789", Space + 1 )) != string::npos )
        {
            string Response = RequestT.substr( DigitPos, 3 );

            if ( sscanf(Response.c_str(), "%d", &HTMLResponse) == 1 )
            {
                return 0;
            }
            else
            {
                if (LL>0) LogFile::ErrorMessage("Unknown server response: %s\n", RequestT.c_str());
            }
        }
    }

    return -230;
}


int ConnectionToHTTP::AnalyseHeaderLine( string &RequestT )
{
    //Optimize checks.. no need to match if header line not long enough

    //"Content-Length: x" needs atleast 17 chars
    //"Connection: Keep-Alive" needs atleast 22 chars

    if ( RequestT.length() > 16 )
    {
        //Uppercase for matching
        string RequestU = UpperCase(RequestT);

        if ( MatchBegin( RequestU, "CONTENT-LENGTH: ", 16 ) )
        {
            if ( RequestU.find_first_not_of("0123456789", 16) != string::npos )
            {
                //Invalid Content-Length
                return 0;
            }

            string LengthToken = RequestT.substr( 16 );

            //Sanity check for invalid huge Content-Length
            if ( LengthToken.length() > 18 ) return 0;

            if ( sscanf(LengthToken.c_str(), "%lld", &ContentLength) != 1 )
            {
                ContentLength = -1;
            }

            return 0;
        }

        if ( MatchSubstr( RequestU, "CONNECTION: KEEP-ALIVE", -1 ) )
        {
            IsKeepAlive = true;

            return 0;
        }

        if ( MatchBegin( RequestU, "CONTENT-TYPE: IMAGE/", 20 ) )
        {
            IsImage = true;

            return 0;
        }

        if ( MatchBegin( RequestU, "TRANSFER-ENCODING: CHUNKED", 26 ) )
        {
            IsChunked = true;

            return 0;
        }

        if ( MatchBegin( RequestU, "TRANSFER-ENCODING: ", 19 ) )
        {
            //Not allowed on HTTP/1.0
            return -232;
        }

    }//End >16 check

    return 0;
}

long long ConnectionToHTTP::GetContentLength()
{
    return ContentLength;
}

int ConnectionToHTTP::GetResponse()
{
    return HTMLResponse;
}

bool ConnectionToHTTP::IsItKeepAlive()
{
    return IsKeepAlive;
}

bool ConnectionToHTTP::IsItImage()
{
    return IsImage;
}

bool ConnectionToHTTP::IsItChunked()
{
    return IsChunked;
}

void ConnectionToHTTP::ClearVars()
{
    ContentLength = -1;
    IsKeepAlive = IsImage = IsChunked = false;
}


//Consturctor
ConnectionToHTTP::ConnectionToHTTP()
{
    HTMLResponse = 0;
    ProxyConnection = false;
}


//Destructor
ConnectionToHTTP::~ConnectionToHTTP()
{
}
