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

#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

string UpperCase( string CaseString )
{
    string::const_iterator si = CaseString.begin();
    string::size_type j = 0;
    string::size_type e = CaseString.size();
    while ( j < e ) { CaseString[j++] = toupper(*si++); }

    return CaseString;
}

void SearchReplace( string &source, string search, string replace )
{
    string::size_type position = source.find(search);

    while (position != string::npos)
    {
        source.replace(position, search.size(), replace);
        position = source.find(search);
    }
}

int select_eintr( int fds, fd_set *readfds, fd_set *writefds, fd_set *errorfds, struct timeval *timeout )
{
    if ( timeout->tv_sec == 0 )
    {
        return select(fds, readfds, writefds, errorfds, timeout);
    }

    int ret;

#ifndef __linux__
    time_t start = time(NULL);
    time_t now;
    int orig_timeout = timeout->tv_sec;
#endif

    while ((ret = select(fds, readfds, writefds, errorfds, timeout)) < 0 && errno == EINTR)
    {
#ifndef __linux__
        now = time(NULL);
        if ((now - start) < orig_timeout)
        {
            timeout->tv_sec = orig_timeout - (now - start);
            timeout->tv_usec = 0;
        }
#endif
    }

    return ret;
}
