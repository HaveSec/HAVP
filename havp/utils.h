/***************************************************************************
                          utils.h  -  description
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

#ifndef UTILS_H
#define UTILS_H

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <vector>

using namespace std;

string UpperCase( string CaseString );
void SearchReplace( string &source, string search, string replace );
int select_eintr( int fds, fd_set *readfds, fd_set *writefds, fd_set *errorfds, struct timeval *timeout );
bool MatchSubstr(string &hay, const char* needle, int startpos);
bool MatchBegin(string &hay, const char *needle, int needlelength);
bool MatchWild(const char *str, const char *pat);
void Tokenize(const string& str, vector<string>& tokens);
string base64_encode(string input);
    
#endif
