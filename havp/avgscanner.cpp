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

//Init scanner engine
bool AVGScanner::InitDatabase()
{
    return true;
}


//Reload scanner engine
bool AVGScanner::ReloadDatabase()
{
    return false;
}


//Start scan
int AVGScanner::Scanning()
{

    char Ready[2];
    int fd;
    ScannerAnswer = "";

    if ( (fd = open(FileName, O_RDONLY)) < 0 )
    {
        LogFile::ErrorMessage("Could not open file to scan: %s\n", FileName);
        ScannerAnswer = "Could not open file to scan";

        close(fd);
        return 2;
    }

    //Wait till file is set up for scanning
    while (read(fd, Ready, 1) < 0 && errno == EINTR);
    close(fd);

    string serverhost = Params::GetConfigString("AVGSERVER");
    int serverport = Params::GetConfigInt("AVGPORT");

    if ( AVGSocket.SetDomainAndPort( serverhost, serverport ) == false )
    {
        LogFile::ErrorMessage("Could not connection to scanner\n");
        ScannerAnswer = "Could not connect to scanner";
        return 2;
    }
    if ( AVGSocket.ConnectToServer() == false )
    {
        LogFile::ErrorMessage("Could not connect to scanner\n");
        ScannerAnswer = "Could not connect to scanner";
        AVGSocket.Close();
        return 2;
    }

    //Construct command for scanner
    string ScannerCmd = "SCAN ";
    ScannerCmd += FileName;
    ScannerCmd += "\r\nQUIT\r\n";

    if ( AVGSocket.Send( &ScannerCmd ) == false )
    {
        AVGSocket.Close();
        LogFile::ErrorMessage("Could not call scanner\n");
        ScannerAnswer = "Could not call scanner";
        return 2;
    }

    string Response;
    int ret;

    while ( (ret = AVGSocket.Recv( &Response, true )) != 0 )
    {
        if (ret < 0)
        {
            AVGSocket.Close();
            LogFile::ErrorMessage("Could not read scanner response\n");
            ScannerAnswer = "Could not read scanner response";
            return 2;
        }
    }

    AVGSocket.Close();

    if ( Response.length() < 20 )
    {
        LogFile::ErrorMessage("Invalid response from scanner\n");
        ScannerAnswer = "Invalid response from scanner";
        return 2;
    }

    string::size_type Position;

    if ( Response.find( "\n200 OK" ) != string::npos )
    {
        ScannerAnswer = "Clean";
        return 0;
    }
    if ( ( Position = Response.find( "\n403 " )) != string::npos )
    {
        string::size_type PositionEnd;

        if ( (PositionEnd = Response.find( "\r", Position + 4 )) != string::npos )
        {
            Position = Response.rfind( " ", PositionEnd );

            ScannerAnswer = Response.substr( Position + 1, PositionEnd - Position - 1 );
        }
        else
        {
            ScannerAnswer = "unknown";
        }

        return 1;
    }

    ScannerAnswer = "Unknown response from scanner";
    return 2;
}


void AVGScanner::FreeDatabase()
{
}

//Constructor
AVGScanner::AVGScanner()
{
}


//Destructor
AVGScanner::~AVGScanner()
{
}
