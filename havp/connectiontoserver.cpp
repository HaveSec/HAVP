/***************************************************************************
                          connectiontoserver.cpp  -  description
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

#include "connectiontoserver.h"

//Prepare Header for Browser
string ConnectionToServer::PrepareHeaderForBrowser()
{

    string header ="";

    vector<string>::iterator it;

    //Edit torken
    for (it = tokens.begin(); it != tokens.end(); ++it)
    {

        if( it->find( "Transfer-encoding", 0 ) == 0 )
        {
            continue;
        } else if ( it->find( "Keep-Alive", 0 ) == 0 )
        {
            continue;
        } else if( it->find( "Connection", 0) == 0 )
        {
            continue;
        } else if( it->find( "Proxy-Connection", 0) == 0 )
        {
            continue;
        }

        header += *it;

    }                                             //for

    header += "Proxy-Connection: Close\r\n\r\n";
    //cout << header << endl;
    return header;

}


bool ConnectionToServer::AnalyseHeaderLine( string *RequestT )
{

   string Response ="";
   string::size_type firstposition;
   string::size_type lastposition;

   if( RequestT->find( "HTTP/1.", 0 ) == 0 )
   {
     if ( (firstposition = RequestT->find_first_not_of("\t ",9)) != string::npos )
     {

      if ( (lastposition = RequestT->find (" ",firstposition+1)) != string::npos ){

       //LogFile::ErrorMessage("Server Response %s\n", RequestT->c_str());

        Response = RequestT->substr(9, lastposition - 9 );
        if (sscanf( Response.c_str(), "%d", &HTMLResponse) != 1)
        {
          LogFile::ErrorMessage("Unknown Server Response %s\n", Response.c_str());
          return false;
        }
      }
    }  
   } 

    return true;
}


int ConnectionToServer::GetResponse()
{
  return HTMLResponse;
}

//Consturctor
ConnectionToServer::ConnectionToServer()
{

 HTMLResponse = 0;

}


//Destructor
ConnectionToServer::~ConnectionToServer()
{
}
