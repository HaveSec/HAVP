/***************************************************************************
                          scannerfilehandler.h  -  description
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

#ifndef SCANNERFILEHANDLER_H
#define SCANNERFILEHANDLER_H

#include "genericscanner.h"
#include "logfile.h"
#include "default.h"

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <unistd.h>
//#include <sys/time.h>
//#include <sys/types.h>
//#include <sys/stat.h>
#include <fcntl.h>

#include <iostream>

using namespace std;


class ScannerFileHandler : public GenericScanner  {

private:
int fd_scan;
unsigned long FileLength;

protected:
char FileName[MAXSCANTEMPFILELENGTH+1];

public:

bool OpenAndLockFile( );

bool UnlockFile();

bool DeleteFile();

bool SetFileSize( unsigned long ContentLengthT );

bool ExpandFile( char *DataT, int lengthT,  bool unlockT );


bool InitDatabase();

bool ReloadDatabase();

int Scanning ();

bool InitSelfEngine();

int ScanningComplete();

char* GetFileName();
                                                                                                                                                         
	ScannerFileHandler();
	~ScannerFileHandler();
};

#endif
