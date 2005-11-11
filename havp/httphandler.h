/***************************************************************************
                          httphandler.h  -  description
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

#ifndef HTTPHANDLER_H
#define HTTPHANDLER_H

#include "sockethandler.h"

#include <iostream>
#include <vector>
#include <string>

#include <stdio.h>
#include <stdarg.h>

//#include <stdlib.h>

using namespace std;

class HTTPHandler : public SocketHandler  {

private:

unsigned long ContentLength;

protected:

vector <string> tokens;

virtual bool AnalyseHeaderLine( string *RequestT ) = 0;

public: 

bool ReadHeader( string *headerT );

bool AnalyseHeader(string *linesT, const char *delimitersT );

unsigned long GetContentLength( );

ssize_t ReadBodyPart( string* bodyT );

bool SendHeader( string* headerT );

  HTTPHandler();
virtual ~HTTPHandler();
};

#endif
