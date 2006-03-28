/***************************************************************************
                          sophiescanner.cpp  -  description
                             -------------------
    begin                : Sa Mar 25 2006
    copyright            : (C) 2006 by Christian Hilgers
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

#include "sophiescanner.h"


bool SophieScanner::InitDatabase()
{
    return true;
}


bool SophieScanner::ReloadDatabase()
{
    return false;
}


string SophieScanner::Scan( const char *FileName )
{
    int fd = open(FileName, O_RDONLY);

    if ( fd < 0 )
    {
        LogFile::ErrorMessage("Sophie: Could not open tempfile: %s\n", strerror(errno));
        ScannerAnswer = "2Could not open file to scan";
        return ScannerAnswer;
    }

    //Wait till file is set up for scanning
    while (read(fd, Ready, 1) < 0 && errno == EINTR);
    while (close(fd) < 0 && errno == EINTR);

    if ( Connected == false )
    {
        //Connect
        if ( SOPHIESocket.ConnectToSocket( Params::GetConfigString("SOPHIESOCKET"), 1 ) == false )
        {
            //Prevent log flooding, show error only once per minute
            if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
            {
                LogFile::ErrorMessage("Sophie: Could not connect to scanner! Scanner down?\n");
                LastError = time(NULL);
            }

            ScannerAnswer = "2Could not connect to scanner socket";
            return ScannerAnswer;
        }

        Connected = true;
    }

    //Construct command for scanner
    ScannerCmd = FileName;
    ScannerCmd += "\n";

    //Send command
    if ( SOPHIESocket.Send( &ScannerCmd ) == false )
    {
        SOPHIESocket.Close();
        Connected = false;

        //Try to reconnect if failed
        if ( SOPHIESocket.ConnectToSocket( Params::GetConfigString("SOPHIESOCKET"), 1 ) == false )
        {
            //Prevent log flooding, show error only once per minute
            if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
            {
                LogFile::ErrorMessage("Sophie: Could not connect to scanner! Scanner down?\n");
                LastError = time(NULL);
            }

            ScannerAnswer = "2Could not connect to scanner socket";
            return ScannerAnswer;
        }

        //Send command.. again
        if ( SOPHIESocket.Send( &ScannerCmd ) == false )
        {
            SOPHIESocket.Close();

            LogFile::ErrorMessage("Sophie: Could not write command to scanner\n");
            ScannerAnswer = "2Scanner connection failed";
            return ScannerAnswer;
        }

        Connected = true;
    }

    string Response;

    //Get response
    if ( SOPHIESocket.Recv( &Response, true, 600 ) < 0 )
    {
        SOPHIESocket.Close();
        LogFile::ErrorMessage("Sophie: Could not read scanner response\n");
        ScannerAnswer = "2Could not read scanner response";
        return ScannerAnswer;
    }

    //Clean?
    if ( Response.find("0", 0, 1) == 0 )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    //Virus?
    if ( Response.find("1", 0, 1) == 0 )
    {
        ScannerAnswer = "1" + Response.substr( 2 );
        return ScannerAnswer;
    }

    //Error?
    if ( Response.find("-1", 0, 2) == 0 )
    {
        ScannerAnswer = "2" + Response.substr( 3 );
        return ScannerAnswer;
    }

    //Unknown answer..
    LogFile::ErrorMessage("Sophie: Unknown response from scanner: %s\n", Response.c_str());
    ScannerAnswer = "2Invalid response from scanner";
    return ScannerAnswer;
}


void SophieScanner::FreeDatabase()
{
}


void SophieScanner::CloseSocket()
{
    SOPHIESocket.Close();
    Connected = false;
}


//Constructor
SophieScanner::SophieScanner()
{
    ScannerName = "Sophie Socket Scanner";

    Connected = false;
    LastError = 0;

    ScannerAnswer.reserve(100);
}


//Destructor
SophieScanner::~SophieScanner()
{
}

