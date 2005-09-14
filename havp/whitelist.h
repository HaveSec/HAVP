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
class URLList {

private:

struct PathStruct
{
 string Path;
 char exact;
};

struct DomainStruct
{
 string Domain;
 char exact;
 vector <struct PathStruct> Path;
};

struct URLListStruct
{
 string Toplevel;
 vector <struct DomainStruct> Domain;
};

vector <URLListStruct> URLListDB;

char CheckItem ( string *ItemT );

bool AnalyseURL( string UrlT, string *ToplevelT, string *DomainT, char *ExactDomainT, string *PathT, char *ExactPathT );

void InsertURL( struct URLListStruct *URLListDBT, string DomainT, char ExactDomainT, string PathT, char ExactPathT );

string DisplayLine( string LineT, char positionT );

bool FindString( string SearchT, string LineT, char positionT );

public:

bool URLFound ( string DomainT, string PathT );

bool CreateURLList(string URLListFileT);

bool ReloadURLList( string URLListFileT );

void DisplayURLList( );

    URLList();

    ~URLList();

};

#endif
