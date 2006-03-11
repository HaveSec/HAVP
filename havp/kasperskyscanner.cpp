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

//Init scanner engine
bool KasperskyScanner::InitDatabase()
{
    return true;
}


//Reload scanner engine
bool KasperskyScanner::ReloadDatabase()
{
    return false;
}


//Start scan
int KasperskyScanner::Scanning()
{

    char buffer[STRINGLENGTH+1];
    char Ready[2];
    int fd, ret;
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

    string::size_type Position;
    string Response;

    if ( Connected == false )
    {
        //Connect
        if ( AVESocket.ConnectToSocket( Params::GetConfigString("AVESOCKET") ) == false )
        {
            AVESocket.Close();
            ScannerAnswer = "Could not connect to scanner socket";
            return 2;
        }

        //Get initial response
        do
        {
            if ( AVESocket.Recv( &Response, false ) == false )
            {
                AVESocket.Close();
                ScannerAnswer = "Could not read from scanner socket";
                return 2;
            }
        }
        while ( (Position = Response.find("\r\n")) == string::npos );

        Response = "";
        if ( AVESocket.RecvLength( &Response, Position + 2 ) == false )
        {
            AVESocket.Close();
            ScannerAnswer = "Could not read from scanner socket";
            return 2;
        }

        //Check greeting
        if ( Response.substr(0, 3) != "201" )
        {
            AVESocket.Close();
            LogFile::ErrorMessage("Invalid greeting from scanner\n");
            ScannerAnswer = "Invalid greeting from scanner";
            return 2;
        }

        Connected = true;
    }

    //Construct command for scanner
    string ScannerCmd = "SCAN xmQPRSTUWabcdefghi ";
    ScannerCmd += FileName;
    ScannerCmd += "\r\n";

    //Send command
    if ( AVESocket.Send( &ScannerCmd ) == false )
    {
        AVESocket.Close();
        Connected = false;
        LogFile::ErrorMessage("Could not write command to scanner\n");
        ScannerAnswer = "Scanner connection failed";
        return 2;
    }

    //Parse response lines
    do
    {
        Response = "";
        do
        {
            if ( AVESocket.Recv( &Response, false ) == false )
            {
                AVESocket.Close();
                Connected = false;
                ScannerAnswer = "Could not read from scanner socket";
                return 2;
            }

        }
        while ( (Position = Response.find("\r\n")) == string::npos );

        Response = "";
        if ( AVESocket.RecvLength( &Response, Position + 2 ) == false )
        {
            AVESocket.Close();
            Connected = false;
            ScannerAnswer = "Could not read from scanner socket";
            return 2;
        }

        //Virus name found
        if ( Response.substr(0, 4) == "322-" )
        {
           if ( (Position = Response.find("/", 4)) != string::npos )
           {
               ScannerAnswer = Response.substr( 4, Position - 5 );
           }
        }
    }
    while ( Response.substr(0, 1) == "3" );

    //Clean
    if ( Response.substr(0, 3) == "220" )
    {
        ScannerAnswer = "Clean";
        return 0;
    }
    //Infected
    else if ( Response.substr(0, 3) == "230" )
    {
        if (ScannerAnswer == "") ScannerAnswer = "unknown";
        return 1;
    }
    //Suspicious
    else if ( Response.substr(0, 3) == "232" )
    {
        if (ScannerAnswer == "") ScannerAnswer = "Suspicious";
        return 1;
    }
    //Scan Error
    else if ( Response.substr(0, 3) == "241" )
    {
        ScannerAnswer = Response;
        return 2;
    }
    //Other Error
    else if ( Response.substr(0, 1) == "5" )
    {
        ScannerAnswer = Response;
        return 2;
    }
    //Other non-fatal responses
    else if ( Response.substr(0, 1) == "2" )
    {
        ScannerAnswer = "Clean";
        return 0;
    }

    LogFile::ErrorMessage("Unknown response from scanner: %s\n", Response.c_str());
    ScannerAnswer = "Unknown scanner response";
    return 2;
}


void KasperskyScanner::FreeDatabase()
{
}

//Constructor
KasperskyScanner::KasperskyScanner()
{
    Connected = false;
}


//Destructor
KasperskyScanner::~KasperskyScanner()
{
}
