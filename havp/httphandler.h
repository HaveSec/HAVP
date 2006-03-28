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

#include <vector>

using namespace std;

class HTTPHandler : public SocketHandler {

protected:

bool ProxyConnection;
vector<string> tokens;

virtual int AnalyseFirstHeaderLine( string *RequestT ) = 0;
virtual int AnalyseHeaderLine( string *RequestT ) = 0;

public:

bool ReadHeader( string *headerT );
int AnalyseHeader( string *linesT );
ssize_t ReadBodyPart( string* bodyT );
bool SendHeader( string header, bool ConnectionClose );

HTTPHandler();
virtual ~HTTPHandler();

};

#endif
