/***************************************************************************
                          scannerhandler.h  -  description
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

#ifndef SCANNERHANDLER_H
#define SCANNERHANDLER_H

#include "default.h"
#include "genericscanner.h"
#include "sockethandler.h"

#include <time.h>
#include <vector>

using namespace std;

class ScannerHandler {

private:

struct scanner_st
{
    int toscanner;
    int fromscanner;
    string scanner_name;
    string scanner_name_short;
    pid_t scanner_pid;
};

struct timeval ZeroTimeout;
struct timeval ScannersTimeout;
int ScannerTimeout;

fd_set readfds, origfds, scannerfds;
int totalscanners, top_fd, answers;

vector<string> ErrorMsg;
vector<string> VirusMsg;

vector<scanner_st> Scanner;
vector<GenericScanner*> VirusScanner;

unsigned long TempFileLength;

public:

int ClamVersion;

bool InitScanners();
bool CreateScanners( SocketHandler &ProxyServerT );
bool ReloadDatabases();
bool RestartScanners();
void ExitScanners();
#ifndef NOMAND
bool HasAnswer();
#endif
int GetAnswer();
string GetAnswerMessage();

bool InitTempFile();
bool UnlockTempFile();
bool DeleteTempFile();
bool ReinitTempFile();
bool SetTempFileSize( long long ContentLengthT );
bool TruncateTempFile( long long ContentLengthT );
bool ExpandTempFile( string &dataT, bool unlockT );
#ifndef NOMAND
bool ExpandTempFileRange( string &dataT, long long offset );
#endif

ScannerHandler();
~ScannerHandler();

};

#endif
