/***************************************************************************
                          params.h  -  description
                             -------------------
    begin                : So Feb 20 2005
    copyright            : (C) 2005 by Peter Sebald / Christian Hilgers
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

#ifndef PARAMS_H
#define PARAMS_H

#include <string>
#include <map>

using namespace std;

class Params {

private:

static map <string,string> params;

static bool ReadConfig( string file );
static void ShowConfig( string cfgfile );
static bool TestConfig();
static void Usage();
static void SetDefaults();

public:

static bool SetParams( int argcT, char* argv[] );
static void SetConfig( string key, string val );
static bool GetConfigBool( string key );
static string GetConfigString( string key );
static int GetConfigInt( string key );

};

#endif
