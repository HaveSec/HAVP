/***************************************************************************
                          utils.cpp  -  description
                             -------------------
    begin                : Sa M� 5 2005
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

#include "utils.h"

#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <cstring>

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

bool MatchBegin(string &hay, const char *needle, int needlelength)
{
    return ( strncmp(hay.c_str(), needle, needlelength) == 0 ) ? true : false;
}
    
bool MatchSubstr(string &hay, const char *needle, int startpos)
{
    if (startpos == -1)
    {
        return ( strstr(hay.c_str(), needle) != NULL ) ? true : false;
    }
    else
    {
        return ( strstr(hay.c_str(), needle) == hay.c_str() + startpos ) ? true : false;
    }
}

bool MatchWild(const char *str, const char *pat)
{
    int i, star;

    if (!str || !pat) return false;

new_segment:

    star = 0;
    if (*pat == '*') {
        star = 1;
        do { pat++; } while (*pat == '*');
    }

test_match:

    for (i = 0; pat[i] && (pat[i] != '*'); i++) {
        if (toupper(str[i]) != toupper(pat[i])) {
            if (!str[i]) return false;
            if (pat[i] == '?') continue;
            if (!star) return false;
            str++;
            goto test_match;
        }
    }
    if (pat[i] == '*') {
        str += i;
        pat += i;
        goto new_segment;
    }
    if (!str[i]) return true;
    if (i && pat[i - 1] == '*') return true;
    if (!star) return false;
    str++;
    goto test_match;
}

void Tokenize(const string& str, vector<string>& tokens)
{
    string::size_type lastPos = str.find_first_not_of(" ", 0);
    string::size_type pos = str.find_first_of(" ", lastPos);

    while (string::npos != pos || string::npos != lastPos)
    {
        tokens.push_back(str.substr(lastPos, pos - lastPos));
        lastPos = str.find_first_not_of(" ", pos);
        pos = str.find_first_of(" ", lastPos);
    }
}

/*
The base64 implementation below is licensed according to:

	Copyright (c) 2001 Bob Trower, Trantor Standard Systems Inc.

	Permission is hereby granted, free of charge, to any person
	obtaining a copy of this software and associated
	documentation files (the "Software"), to deal in the
	Software without restriction, including without limitation
	the rights to use, copy, modify, merge, publish, distribute,
	sublicense, and/or sell copies of the Software, and to
	permit persons to whom the Software is furnished to do so,
	subject to the following conditions:

	The above copyright notice and this permission notice shall
	be included in all copies or substantial portions of the
	Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
	KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
	WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
	PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
	OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
	OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/*
** Translation Table as described in RFC1113
*/
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
** encodeblock
**
** encode 3 8-bit binary bytes as 4 '6-bit' characters
*/
void encodeblock( unsigned char in[3], unsigned char out[4], int len )
{
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

string base64_encode(string input) {
	string base64 = "";
	unsigned char result[5];
	memset(result, 0x00, 5);
	for(unsigned int i = 0; i < input.length(); i += 3) {
		string block = input.substr(i,3);
		encodeblock((unsigned char*)block.c_str(), result, block.length());
		base64.append((const char*)result);
	}
	return base64;
}

