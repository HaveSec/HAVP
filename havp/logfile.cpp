/***************************************************************************
                          logfile.cpp  -  description
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

#include "logfile.h"
#include "params.h"

int LogFile::Access_fd;
int LogFile::Error_fd;

//Open access and error logfiles
bool LogFile::InitLogFiles ( const char *AccessLogFileT, const char *ErrorLogFileT )
{

    if ( (Error_fd = open(ErrorLogFileT, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0)
    {
        return false;
    }

    if ( (Access_fd = open(AccessLogFileT, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0)
    {
        return false;
    }

    return true;
}


//Log access messages
void LogFile::AccessMessage( const char *formatT , ... )
{
    va_list args;
    char str[STRINGLENGTH+1];

    string Message = GetDateAndTime() + " ";

    va_start(args, formatT);

    vsnprintf(str, STRINGLENGTH, formatT, args);
    Message.append(str);

    memset(&str, 0, sizeof(str));
    Message.copy(str, STRINGLENGTH);

    write(Access_fd, str, strlen(str));

    va_end(args);
}


//Log error messages
void LogFile::ErrorMessage( const char *formatT , ... )
{
    va_list args;
    char str[STRINGLENGTH+1];

    string Message = GetDateAndTime() + " ";

    va_start(args, formatT);

    vsnprintf(str, STRINGLENGTH, formatT, args);
    Message.append(str);
    
    memset(&str, 0, sizeof(str));
    Message.copy(str, STRINGLENGTH);

    write(Error_fd, str, strlen(str));

    va_end(args);
}


string LogFile::GetDateAndTime()
{
    string DateString;
    char tmpdate[51];
    struct tm TmDate;
    time_t LogTime;

    time(&LogTime);
    TmDate = *localtime(&LogTime);
    strftime(tmpdate, 50, TIMEFORMAT, &TmDate);
    DateString.assign(tmpdate);

    return DateString;
}
