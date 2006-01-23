/***************************************************************************
                          trophiescanner.h  -  description
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

#ifndef TROPHIESCANNER_H
#define TROPHIESCANNER_H

#include <trophie.h>

#include "scannerfilehandler.h"

class TrophieScanner : public ScannerFileHandler  {

private:

struct trophie_vs_type trophie_vs;
struct pattern_info_ex_type pattern_info_ex;

int trophie_scanfile(char *scan_file);
static int vs_callback(char *a, struct callback_type *b, int c, char *d);

static char VIR_NAME[512];



int vs_addr;
int cur_patt;

public:


bool InitDatabase();

bool ReloadDatabase();

bool InitSelfEngine();

//PSEstart
bool FreeDatabase();
//PSEend

int ScanningComplete();

int Scanning();

	TrophieScanner();
	~TrophieScanner();
};

#endif
