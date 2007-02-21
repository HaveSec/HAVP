/***************************************************************************
                          arcavirscanner.h  -  description
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

#ifndef ARCAVIRSCANNER_H
#define ARCAVIRSCANNER_H

#include "../genericscanner.h"

class ArcavirScanner : public GenericScanner {

private:

string ScannerCmd;

SocketHandler ArcavirSocket;
time_t LastError;

string ScannerAnswer;
char Ready[2];

public:

bool InitDatabase();
bool ReloadDatabase();
void FreeDatabase();
string Scan( const char *FileName );

ArcavirScanner();
~ArcavirScanner();

};

#endif