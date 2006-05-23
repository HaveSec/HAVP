/***************************************************************************
                          genericscanner.h  -  description
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

#ifndef GENERICSCANNER_H
#define GENERICSCANNER_H

#include "default.h"
#include "sockethandler.h"
#include "logfile.h"
#include "params.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <string>

using namespace std;

class GenericScanner {

public:

string ScannerName;
string ScannerNameShort;

bool StartScanning( int fromhandler, int tohandler, const char *FileName );

virtual bool InitDatabase() = 0;
virtual bool ReloadDatabase() = 0;
virtual void FreeDatabase() = 0;
virtual string Scan( const char *FileName ) = 0;

virtual void CloseSocket();

GenericScanner();
virtual ~GenericScanner();

};

#endif
