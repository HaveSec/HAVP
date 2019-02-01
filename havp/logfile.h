/***************************************************************************
                          logfile.h  -  description
                             -------------------
    begin                : Sa Feb 12 2005
    copyright            : (C) 2005 by Christian Hilgers
    email                : christian@havp.org
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

#include <string>

using namespace std;

class LogFile {

private:

static string TimeFormat;

static int Error_fd;
static int Virus_fd;
static int Access_fd;

static bool UseSyslog;
static int SyslogLevel;
static int SyslogVirusLevel;

static int GetSyslogLevel();
static int GetSyslogVirusLevel();
static int GetSyslogFacility();

public:

static bool InitLogFiles( const char *AccessLogFileT, const char *VirusLogFileT, const char *ErrorLogFileT );
static void AccessMessage( const char *formatT, ... );
static void VirusMessage( const char *formatT, ... );
static void ErrorMessage( const char *formatT, ... );
   
};

#endif
