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

#include "scannerfilehandler.h"
#include <sys/socket.h>
#include <sys/un.h>

class KasperskyScanner : public ScannerFileHandler  {

private:

SocketHandler AVESocket;

bool Connected;

public:

bool InitDatabase();

bool ReloadDatabase();

void FreeDatabase();

int Scanning();

	KasperskyScanner();
	~KasperskyScanner();
};

#endif
