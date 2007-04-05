/***************************************************************************
                          kasperskyscanner.h  -  description
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

#ifndef KASPERSKYSCANNER_H
#define KASPERSKYSCANNER_H

#include "../genericscanner.h"

class KasperskyScanner : public GenericScanner {

private:

string ScannerCmd;
bool Connected;

SocketHandler AVESocket;
time_t LastError;

string ScannerAnswer;
char Ready[2];

public:

bool InitDatabase();
int ReloadDatabase();
void FreeDatabase();
string Scan( const char *FileName );

void CloseSocket();

KasperskyScanner();
~KasperskyScanner();

};

#endif
