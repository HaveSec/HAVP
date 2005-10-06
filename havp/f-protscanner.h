/***************************************************************************
                          FProtScanner.h  -  description
                             -------------------
    begin                : Mit Jun 29 2005
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

#ifndef FPROTSCANNER_H
#define FPROTSCANNER_H

#include "genericscanner.h"
#include "scannerfilehandler.h"
#include "logfile.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include <stdarg.h>
#include <stdio.h>

using namespace std;

class FProtScanner : public ScannerFileHandler  {


public:

bool InitDatabase();

bool ReloadDatabase();

bool InitSelfEngine();

int ScanningComplete();

int Scanning( );


	FProtScanner();
	~FProtScanner();
};

#endif
