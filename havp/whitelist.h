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

#include <string>
#include <iostream>
#include <vector>
#include <map>

using namespace std;

/**
@author Christian Hilgers
*/
class URLList {

private:

struct PathStruct
{
 string Path;
 char ExactPath;
 char ExactDomain;
 
};

/*
struct DomainStruct
{
 vector <struct PathStruct> Path;
};
*/

map <string, vector <struct PathStruct> > URLLists;

char CheckItem ( string *ItemT );

bool AnalyseURL( string UrlT, string *DomainT, char *ExactDomainT, string *PathT, char *ExactPathT );


string DisplayLine( string LineT, char positionT );

bool FindString( string *SearchT, string *LineT, char positionT );

bool Search ( string *DomainT, char ExactDomainT, string *PathT );

public:

bool URLFound ( string DomainT, string PathT );

bool CreateURLList(string URLListFileT);

bool ReloadURLList( string URLListFileT );

void DisplayURLList( );

    URLList();

    ~URLList();

};

#endif
