/***************************************************************************
                          clamlibscanner.h  -  description
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

#ifndef CLAMLIBSCANNER_H
#define CLAMLIBSCANNER_H

#include "../genericscanner.h"

#include <clamav.h>

using namespace std;

class ClamLibScanner : public GenericScanner {

private:

string ScannerAnswer;
char Ready[2];

const char *virname;

struct cl_node *root;
struct cl_limits limits;
struct cl_stat dbstat;
char dbdir[255];

int scanopts;

public:

bool InitDatabase();
bool ReloadDatabase();
void FreeDatabase();
string Scan( const char *FileName );

ClamLibScanner();
~ClamLibScanner();

};

#endif
