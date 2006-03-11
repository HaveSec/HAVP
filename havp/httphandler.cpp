/***************************************************************************
                          httphandler.cpp  -  description
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

#include "httphandler.h"
#include "logfile.h"
#include "utils.h"

//Read header
bool HTTPHandler::ReadHeader( string *headerT )
{

    string::size_type position;
    bool WrongHeader = false;
    int poscount = 0;
    ssize_t read;
    string tempheader;

    *headerT = "";

    if ( (read = SocketHandler::Recv( &tempheader, false )) <= 0 )
    {
        return false;
    }

    while ( (position = tempheader.find ("\r\n\r\n")) == string::npos )
    {
        //Maybe we should also look for \n\n (19.3 RFC 1945 - Tolerant Applications)
        if ( (position = tempheader.find ("\n\n")) != string::npos )
        {
            WrongHeader = true;
            break;
        }

        //Header not yet found
        //Read and delete part of header containing no \r\n\r\n
        if ( SocketHandler::RecvLength( headerT, read ) == false )
        {
            return false;
        }

        poscount += read;

        //Too big header
        if ( poscount > 20480 )
        {
            LogFile::ErrorMessage("Server sent too big header (>20kB)\n");
            return false;
        }

        if ( (read = SocketHandler::Recv( &tempheader, false )) <= 0 )
        {
            return false;
        }

    }

    //Read last part of header
    if ( SocketHandler::RecvLength( headerT, position - poscount + 2 ) == false )
    {
        return false;
    }

    if ( WrongHeader == false )
    {
        //Read last \r\n
        if ( SocketHandler::RecvLength(&tempheader, 2 ) == false )
        {
            return false;
        }
    }

    return true;
}


//Split header to tokens
int HTTPHandler::AnalyseHeader( string *linesT )
{

    //Delete header tokens
    tokens.clear();

    string::size_type lastposition = 0;

    //Do "Tolerant Applications" - RFC 1945 - Hypertext Transfer Protocol -- HTTP/1.0
    while ( (lastposition = linesT->find( "\r", lastposition )) != string::npos )
    {
        linesT->replace( lastposition, 1, "" );
    }

    int ret;
    bool First = true;
    string tempToken;
    lastposition = 0;

    string::size_type length = linesT->length();

    string::size_type position;
    
    if ( (position = linesT->find( "\n", 0 )) == string::npos )
    {
        return -201;
    }

    while ( position != string::npos && lastposition != length )
    {
        tempToken = linesT->substr( lastposition, position - lastposition );

        if ( (lastposition = tempToken.find_last_not_of("\t ")) != string::npos )
        {
            tempToken = tempToken.substr( 0, lastposition + 1 );

            if ( First == true )
            {
                if ( (ret = AnalyseFirstHeaderLine( &tempToken )) < 0 )
                {
                    return ret;
                }
                First = false;
            }
            else if ( (ret = AnalyseHeaderLine( &tempToken )) < 0 )
            {
                return ret;
            }

            tokens.push_back( tempToken + "\r\n" );
        }

        lastposition = position + 1;
        position = linesT->find( "\n", lastposition );
    }

    return 0;
}


//Read part of Body
ssize_t HTTPHandler::ReadBodyPart( string* bodyT )
{

    *bodyT = "";
    ssize_t count;

    if ( (count = SocketHandler::Recv( bodyT, true )) < 0)
    {
        return -1;
    }

    return count;
}


//Send Header
bool HTTPHandler::SendHeader( string header, bool ConnectionClose )
{
    if ( ProxyConnection ) header += "Proxy-";

    if ( ConnectionClose )
    {
        header += "Connection: close\r\n\r\n";
    }
    else
    {
        header += "Connection: Keep-Alive\r\n\r\n";
    }

    if ( SocketHandler::Send( &header ) == false )
    {
        return false;
    }

    return true;
}



//Constructor
HTTPHandler::HTTPHandler()
{
}


//Destructor
HTTPHandler::~HTTPHandler()
{
}
