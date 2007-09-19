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

#include "../genericscanner.h"

class FProtScanner : public GenericScanner {

private:

string ServerHost;
int ServerPort;

string ScannerCmd;

SocketHandler Scanner;
time_t LastError;

string ScannerAnswer;
char Ready[2];

bool Connected;
int Version;
string Opts;

string ScanV6( const char *FileName );
string ScanV4( const char *FileName );
int TestVersion();
bool ConnectScanner();

public:

bool InitDatabase();
int ReloadDatabase();
void FreeDatabase();
string Scan( const char *FileName );
void CloseSocket();

FProtScanner();
~FProtScanner();

};

#endif
