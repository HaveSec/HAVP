/***************************************************************************
                          nod32scanner.h  -  description
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

#ifndef NOD32SCANNER_H
#define NOD32SCANNER_H

#include "../genericscanner.h"

class NOD32Scanner : public GenericScanner {

private:

string Agent;
int Version;

string ScannerCmd;

SocketHandler NOD32Socket;
time_t LastError;

string ScannerAnswer;
char Ready[2];

string ScanV25( const char *FileName );
string ScanV21( const char *FileName );

public:

bool InitDatabase();
int ReloadDatabase();
void FreeDatabase();
string Scan( const char *FileName );

NOD32Scanner();
~NOD32Scanner();

};

#endif
