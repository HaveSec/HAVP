/***************************************************************************
                          utils.cpp  -  description
                             -------------------
    begin                : Sa M� 5 2005
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

#include "utils.h"

string UpperCase( string CaseString )
{
    string::const_iterator si = CaseString.begin();
    string::size_type j = 0;
    string::size_type e = CaseString.size();
    while ( j < e ) { CaseString[j++] = toupper(*si++); }

    return CaseString;
}


void SearchReplace( string *source, string search, string replace )
{
    string::size_type position = source->find(search);

    while (position != string::npos)
    {
        source->replace(position, search.size(), replace);
        position = source->find(search);
    }
}
