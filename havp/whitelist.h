/***************************************************************************
                          whitelist.h  -  description
                             -------------------
    begin                : Don Aug 18 2005
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

#ifndef WHITELIST_H
#define WHITELIST_H

#include <iostream>
#include <vector>

using namespace std;

/**
@author Christian Hilgers
*/
class Whitelist{

private:

struct PathStruct
{
 string Page;
 char exact;
};

struct URLStruct
{
 string Domain;
 bool exact;
 vector <struct PathStruct> Path;
};

struct WhitelistStruct
{
 string Toplevel;
 vector <struct URLStruct> URL;
};

vector <WhitelistStruct> WhitelistDB;


bool AnalyseURL( string UrlT );

char CheckItem ( string *ItemT );

public:

bool CreateWhitelist(string WhitelistFileT);

    Whitelist();

    ~Whitelist();

};

#endif
