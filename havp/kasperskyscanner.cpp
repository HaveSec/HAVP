/***************************************************************************
                          kasperskyscanner.cpp  -  description
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

#include "kasperskyscanner.h"
#include <sys/types.h>
#include <sys/wait.h>

//Init scanner engine
bool KasperskyScanner::InitDatabase()
{
    return true;
}


//Reload scanner engine
bool KasperskyScanner::ReloadDatabase()
{
    return true;
}


//Start scan
int KasperskyScanner::Scanning( )
{

//    string user=Params::GetConfigString("AVECLIENT");
//    string group=Params::GetConfigString("AVEOPTION");

    string ScannerCall = Params::GetConfigString("AVECLIENT") + KASPERSKYOPTION + Params::GetConfigString("AVESOCKET") + " " + FileName;

    ScannerAnswer="";
    FILE *Output;
    char Lines[500];
    string Line;
    char Ready[1];
    int fd;

    if ( ( fd = open(FileName, O_RDONLY)) < 0)
    {
        LogFile::ErrorMessage ("Could not open file to scan: %s\n", FileName );
        ScannerAnswer="Could not open file to scan";
//PSEstart
	//PSE: We are child but parent process wants this answer to know!
    	WriteScannerAnswer();
//PSEend
        close(fd);
        exit (2);
    }
    //Wait till file is set up for scanning
    read(fd, Ready, 1);
    close(fd);

    Output = popen( ScannerCall.c_str() , "r");

    //Read lines
    fgets( Lines, sizeof Lines, Output);
    Line = Lines;
    if ( Line.rfind("OK") == (Line.size()-3) )
    {
      ScannerAnswer="Clean";
      WriteScannerAnswer();
      pclose(Output);
      exit (0);
    } else if (Line.rfind("INFECTED") == (Line.size()-9) )
    {
      fgets( Lines, sizeof Lines, Output);
      Line = Lines;
      string::size_type start = Line.find(" ");
      ScannerAnswer= Line.substr(start,  Line.size() - start );
      WriteScannerAnswer();
      pclose(Output);
      exit (1);
    }
    fgets( Lines, sizeof Lines, Output);
    ScannerAnswer=Lines;
    WriteScannerAnswer();
    pclose(Output);
    exit (2);

}


//Init scanning engine - do filelock and so on
bool KasperskyScanner::InitSelfEngine()
{

    if( OpenAndLockFile() == false)
    {
        return false;
    }

    return true;
}


int KasperskyScanner::ScanningComplete()
{

    int status=0;

    UnlockFile();

    //Wait till scanning is complete
    waitpid( ScannerPid, &status, 0);

    //Delete scanned file
    DeleteFile();

    //Virus found ? 0=No ; -1=Yes; -2=Scanfail
    return WEXITSTATUS(status);

}

bool KasperskyScanner::FreeDatabase()
{
	return true;
}

//Constructor
KasperskyScanner::KasperskyScanner()
{

}


//Destructor
KasperskyScanner::~KasperskyScanner()
{
}
