/***************************************************************************
                          logfile.h  -  description
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

#ifndef LOGFILE_H
#define LOGFILE_H

#include "default.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>

#include <iostream>
#include <string>

using namespace std;


class LogFile {

private:

static int Error_fd;
static int Access_fd;

static void WriteDateAndTime( int fdT );

public:

static bool InitLogFiles ( const char *AccessLogFileT, const char *ErrorLogFileT );

static void AccessMessage( const char *formatT, ... );

static void ErrorMessage( const char *formatT, ... );
   
};

#endif
