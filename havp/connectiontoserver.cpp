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
     }

     header += *it;

   }//for

   header += "Proxy-Connection: Close\r\n\r\n";
//cout << header << endl;
return header;

}

//Consturctor
ConnectionToServer::ConnectionToServer(){
}

//Destructor
ConnectionToServer::~ConnectionToServer(){
}
