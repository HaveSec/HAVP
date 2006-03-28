/***************************************************************************
                          avgscanner.cpp  -  description
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

#include "avgscanner.h"


bool AVGScanner::InitDatabase()
{
    return true;
}


bool AVGScanner::ReloadDatabase()
{
    return false;
}


string AVGScanner::Scan( const char *FileName )
{
    int fd = open(FileName, O_RDONLY);

    if ( fd < 0 )
    {
        LogFile::ErrorMessage("AVG: Could not open tempfile: %s\n", strerror(errno));
        ScannerAnswer = "2Could not open file to scan";
        return ScannerAnswer;
    }

    //Wait till file is set up for scanning
    while (read(fd, Ready, 1) < 0 && errno == EINTR);
    while (close(fd) < 0 && errno == EINTR);

    if ( AVGSocket.SetDomainAndPort( ServerHost, ServerPort ) == false )
    {
        LogFile::ErrorMessage("AVG: Could not connect to scanner\n");
        ScannerAnswer = "2Could not connect to scanner";
        return ScannerAnswer;
    }
    if ( AVGSocket.ConnectToServer() == false )
    {
        AVGSocket.Close();

        //Prevent log flooding, show error only once per minute
        if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
        {
            LogFile::ErrorMessage("AVG: Could not connect to scanner! Scanner down?\n");
            LastError = time(NULL);
        }

        ScannerAnswer = "2Could not connect to scanner";
        return ScannerAnswer;
    }

    //Construct command for scanner
    ScannerCmd = "SCAN ";
    ScannerCmd += FileName;
    ScannerCmd += "\r\nQUIT\r\n";

    if ( AVGSocket.Send( &ScannerCmd ) == false )
    {
        AVGSocket.Close();
        LogFile::ErrorMessage("AVG: Could not connect to scanner\n");
        ScannerAnswer = "2Could not call scanner";
        return ScannerAnswer;
    }

    string Response;
    int ret;

    while ( (ret = AVGSocket.Recv( &Response, true, 600 )) != 0 )
    {
        if (ret < 0)
        {
            AVGSocket.Close();
            LogFile::ErrorMessage("AVG: Could not read scanner response\n");
            ScannerAnswer = "2Could not read scanner response";
            return ScannerAnswer;
        }
    }

    AVGSocket.Close();

    if ( Response.length() < 20 )
    {
        LogFile::ErrorMessage("AVG: Invalid response from scanner\n");
        ScannerAnswer = "2Invalid response from scanner";
        return ScannerAnswer;
    }

    if ( Response.find( "\n200 OK" ) != string::npos )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    string::size_type Position;

    if ( ( Position = Response.find( "Virus identified " )) != string::npos )
    {
        string::size_type PositionEnd;

        if ( (PositionEnd = Response.find_first_of(" (\r\n", Position + 17 )) != string::npos )
        {
            ScannerAnswer = "1" + Response.substr( Position + 17, PositionEnd - (Position + 17) );
        }
        else
        {
            ScannerAnswer = "1Unknown";
        }

        return ScannerAnswer;
    }

    ScannerAnswer = "2Unknown response from scanner";
    return ScannerAnswer;
}


void AVGScanner::FreeDatabase()
{
}


//Constructor
AVGScanner::AVGScanner()
{
    ScannerName = "AVG Socket Scanner";

    LastError = 0;

    ServerHost = Params::GetConfigString("AVGSERVER");
    ServerPort = Params::GetConfigInt("AVGPORT");

    ScannerAnswer.reserve(100);
}


//Destructor
AVGScanner::~AVGScanner()
{
}
