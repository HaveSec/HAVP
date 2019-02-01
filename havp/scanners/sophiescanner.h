/***************************************************************************
                          kasperskyscanner.h  -  description
                             -------------------
    begin                : Sa Mar 25 2006
    copyright            : (C) 2006 by Christian Hilgers
    email                : christian@havp.org
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef SOPHIESCANNER_H
#define SOPHIESCANNER_H

#include "../genericscanner.h"

class SophieScanner : public GenericScanner {

private:

string ScannerCmd;
bool Connected;

SocketHandler SOPHIESocket;
time_t LastError;

string ScannerAnswer;
char Ready[2];

public:

bool InitDatabase();
int ReloadDatabase();
void FreeDatabase();
string Scan( const char *FileName );

void CloseSocket();

SophieScanner();
~SophieScanner();

};

#endif
