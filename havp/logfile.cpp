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

int LogFile::Access_fd;
int LogFile::Error_fd;

//Open access and error logfiles
bool LogFile::InitLogFiles ( const char *AccessLogFileT, const char *ErrorLogFileT )
{

   if ( (Error_fd = open(ErrorLogFileT, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0){
    return false; }

   if ( (Access_fd = open(AccessLogFileT, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0){
    return false; }

return true;
}

//Log access messages
void LogFile::AccessMessage( const char *formatT , ... )
{
  va_list args;

	string TimeString;

	char str[STRINGLENGTH+1];

	va_start(args, formatT);

	vsnprintf(str, STRINGLENGTH, formatT, args);

  WriteDateAndTime(Access_fd);
  
  write(Access_fd, str, strlen(str));
  
	va_end(args);

}


//Log error messages
void LogFile::ErrorMessage( const char *formatT , ... )
{
  va_list args;

	string TimeString;

	char str[STRINGLENGTH+1];

	va_start(args, formatT);

	vsnprintf(str, STRINGLENGTH, formatT, args);

  WriteDateAndTime(Error_fd);
  
  write(Error_fd, str, strlen(str));
  
	va_end(args);

}

void LogFile::WriteDateAndTime(int fdT)
{
char DateString[51];
struct tm TmDate;
time_t LogTime;

  time( &LogTime );
  
  TmDate = *localtime ( &LogTime );
  strftime (DateString, 50, TIMEFORMAT, &TmDate);
  write( fdT,  DateString , strlen(DateString) );
  write( fdT,  " " , 1 );
  
}
