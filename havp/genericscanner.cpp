/***************************************************************************
                          genericscanner.cpp  -  description
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

#include "genericscanner.h"


bool GenericScanner::StartScanning( int fromhandler, int tohandler, const char *TempFileName )
{
    string ScannerAnswer;
    ScannerAnswer.reserve(100);

    char buf[100];
    int ret;

    for(;;)
    {
        //Start scanner and get return code
        ScannerAnswer = Scan( TempFileName );

        memset(&buf, 0, sizeof(buf));
        ScannerAnswer.copy(buf, 99);

        //Send answer to ScannerHandler
        while ((ret = write(tohandler, buf, 100)) < 0)
        {
            if (errno == EINTR) continue;
            break;
        }
        if (ret <= 0) break; //Pipe was closed - or some bad error

        //Wait for ScannerHandler to finish before we loop again - important
        while ((ret = read(fromhandler, buf, 1)) < 0)
        {
            if (errno == EINTR) continue;
            break;
        }
        if (ret <= 0) break; //Pipe was closed - or some bad error

        //Continue scanning?
        if (buf[0] == 'q') break;
    }

    //End Scanning loop
    return false;
}


bool GenericScanner::InitDatabase()
{
    LogFile::ErrorMessage("Program Error: InitDatabase()\n");
    return false;
}
bool GenericScanner::ReloadDatabase()
{
    LogFile::ErrorMessage("Program Error: ReloadDatabase()\n");
    return false;
}
void GenericScanner::FreeDatabase()
{
    LogFile::ErrorMessage("Program Error: FreeDatabase()\n");
}
string GenericScanner::Scan( const char *TempFileName )
{
    LogFile::ErrorMessage("Program Error: Scan()\n");
    return "";
}

//Scanner might not have this function, so this is allowed
void GenericScanner::CloseSocket()
{
}

//Constructor
GenericScanner::GenericScanner()
{
}

//Destructor
GenericScanner::~GenericScanner()
{
}
