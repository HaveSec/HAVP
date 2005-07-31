/***************************************************************************
                          connectiontoserver.h  -  description
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

#ifndef CONNECTIONTOSERVER_H
#define CONNECTIONTOSERVER_H

#include "httphandler.h"
#include "logfile.h"

class ConnectionToServer : public HTTPHandler  {

private:

 bool AnalyseHeaderLine( string *RequestT );
 int HTMLResponse;


public: 

string PrepareHeaderForBrowser();
int GetResponse( );

  ConnectionToServer();
	~ConnectionToServer();
};

#endif
