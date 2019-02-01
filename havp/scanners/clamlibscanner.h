/***************************************************************************
                          clamlibscanner.h  -  description
                             -------------------
    begin                : 2005/02/12
    last                 : 2019/02/02
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

#ifdef CL_INIT_DEFAULT
struct cl_engine *engine;
#else
struct cl_node *engine;
struct cl_limits limits;
#endif
struct cl_stat dbstat;
char dbdir[255];

struct cl_scan_options cl_options;

public:

bool InitDatabase();
int ReloadDatabase();
void FreeDatabase();
string Scan( const char *FileName );

ClamLibScanner();
~ClamLibScanner();

};

#endif
