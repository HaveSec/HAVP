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

#include "sockethandler.h"
#include "logfile.h"


#include <sys/types.h>
#include  <errno.h>
#include <iostream>
#include <string>

using namespace std;


class GenericScanner {


protected:

string ScannerAnswer;


public:

int commin[2];
int commout[2];

void WriteScannerAnswer ();

string ReadScannerAnswer ();

int CheckScanner ( bool blocking );

bool PrepareScanning ( SocketHandler *ProxyServerT );

bool CreatePipes ();

// Scannerfilehandler

virtual bool InitDatabase() = 0;

virtual bool ReloadDatabase() = 0;

virtual void FreeDatabase() = 0;

virtual int Scanning() = 0;

virtual bool SetFileSize( long long ContentLengthT ) = 0;

virtual bool ExpandFile( string *dataT, bool unlockT ) = 0;

// Scanner

virtual bool OpenAndLockFile() = 0;

virtual bool UnlockFile() = 0;

virtual bool DeleteFile() = 0;

virtual bool ReinitFile() = 0;

virtual bool TruncateFile( long long ContentLengthT ) = 0;

virtual ~GenericScanner ();

GenericScanner ();

};


#endif
