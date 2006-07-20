/***************************************************************************
                          connectiontohttp.h  -  description
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

#ifndef CONNECTIONTOHTTP_H
#define CONNECTIONTOHTTP_H

#include "httphandler.h"

class ConnectionToHTTP : public HTTPHandler {

private:

int HTMLResponse;
long long ContentLength;
bool KeepAlive;
bool IsImage;

int AnalyseFirstHeaderLine( string &RequestT );
int AnalyseHeaderLine( string &RequestT );

public: 

string PrepareHeaderForBrowser();
int GetResponse();
long long GetContentLength();
bool KeepItAlive();
bool ContentImage();
void ClearVars();

ConnectionToHTTP();
~ConnectionToHTTP();

};

#endif
