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

#include <pthread.h>

#include <iostream>

using namespace std;


class GenericScanner {

private:

protected:

pthread_t ScannerThread;

static pthread_mutex_t scan_mutex;

string ScannerAnswer;

string ErrorAnswer;

public:

void WriteScannerAnswer ();

string ReadScannerAnswer ();

string ReadErrorAnswer ();

bool PrepareScanning ( void *GenericScannerT );

static void *CallScanner ( void *prt );


virtual bool InitDatabase() = 0;

virtual bool ReloadDatabase() = 0;

virtual int Scanning () = 0;

virtual bool InitSelfEngine() = 0;

virtual bool ScanningComplete() = 0;

virtual bool SetFileSize( unsigned long ContentLengthT ) = 0;

virtual bool ExpandFile( char *dataT, int lengthT , bool unlockT) = 0 ;

virtual ~GenericScanner ();

GenericScanner ();

};


#endif
