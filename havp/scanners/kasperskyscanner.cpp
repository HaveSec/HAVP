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


bool KasperskyScanner::InitDatabase()
{
    return true;
}


bool KasperskyScanner::ReloadDatabase()
{
    return false;
}


string KasperskyScanner::Scan( const char *FileName )
{
    int fd = open(FileName, O_RDONLY);

    if ( fd < 0 )
    {
        LogFile::ErrorMessage("KAV: Could not open tempfile: %s\n", strerror(errno));
        ScannerAnswer = "2Could not open file to scan";
        return ScannerAnswer;
    }

    //Wait till file is set up for scanning
    while (read(fd, Ready, 1) < 0 && errno == EINTR);
    while (close(fd) < 0 && errno == EINTR);

    string Response;

    if ( Connected == false )
    {
        //Connect
        if ( AVESocket.ConnectToSocket( Params::GetConfigString("AVESOCKET"), 1 ) == false )
        {
            //Prevent log flooding, show error only once per minute
            if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
            {
                LogFile::ErrorMessage("KAV: Could not connect to scanner! Scanner down?\n");
                LastError = time(NULL);
            }

            ScannerAnswer = "2Could not connect to scanner socket";
            return ScannerAnswer;
        }

        //Get initial response
        if ( AVESocket.GetLine( &Response, "\r\n", 600 ) == false )
        {
            AVESocket.Close();

            ScannerAnswer = "2Could not read from scanner socket";
            return ScannerAnswer;
        }

        //Check greeting
        if ( Response.find("201", 0, 3) == string::npos )
        {
            AVESocket.Close();

            LogFile::ErrorMessage("KAV: Invalid greeting from scanner\n");
            ScannerAnswer = "2Invalid greeting from scanner";
            return ScannerAnswer;
        }

        Connected = true;
    }

    //Construct command for scanner
    ScannerCmd = "SCAN xmQPRSTUWabcdefghi ";
    ScannerCmd += FileName;
    ScannerCmd += "\r\n";

    //Send command
    if ( AVESocket.Send( &ScannerCmd ) == false )
    {
        AVESocket.Close();
        Connected = false;

        //Try to reconnect if failed
        if ( AVESocket.ConnectToSocket( Params::GetConfigString("AVESOCKET"), 1 ) == false )
        {
            //Prevent log flooding, show error only once per minute
            if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
            {
                LogFile::ErrorMessage("KAV: Could not connect to scanner! Scanner down?\n");
                LastError = time(NULL);
            }

            ScannerAnswer = "2Could not connect to scanner socket";
            return ScannerAnswer;
        }

        //Get initial response
        if ( AVESocket.GetLine( &Response, "\r\n", 600 ) == false )
        {
            AVESocket.Close();

            ScannerAnswer = "2Could not read from scanner socket";
            return ScannerAnswer;
        }

        //Check greeting
        if ( Response.find("201", 0, 3) == string::npos )
        {
            AVESocket.Close();

            LogFile::ErrorMessage("KAV: Invalid greeting from scanner\n");
            ScannerAnswer = "2Invalid greeting from scanner";
            return ScannerAnswer;
        }

        //Send command.. again
        if ( AVESocket.Send( &ScannerCmd ) == false )
        {
            AVESocket.Close();

            LogFile::ErrorMessage("KAV: Could not write command to scanner\n");
            ScannerAnswer = "2Scanner connection failed";
            return ScannerAnswer;
        }

        Connected = true;
    }

    ScannerAnswer = "";

    //Parse response lines
    do
    {
        if ( AVESocket.GetLine( &Response, "\r\n", 600 ) == false )
        {
            AVESocket.Close();
            Connected = false;

            ScannerAnswer = "2Could not read from scanner socket";
            return ScannerAnswer;
        }

        //Virus name found
        if ( Response.find("322-", 0, 4) == 0 )
        {
            string::size_type Position;

            if ( (Position = Response.find("/", 4)) != string::npos )
            {
                ScannerAnswer = "1" + Response.substr( 4, Position - 5 );
            }
        }
    }
    while ( Response.find("3", 0, 1) == 0 );

    //Clean
    if ( Response.find("220", 0, 3) == 0 )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }
    //Infected
    else if ( Response.find("230", 0, 3) == 0 )
    {
        if (ScannerAnswer == "") ScannerAnswer = "1Unknown";
        return ScannerAnswer;
    }
    //Suspicious
    else if ( Response.find("232", 0, 3) == 0 )
    {
        if (ScannerAnswer == "") ScannerAnswer = "1Suspicious";
        return ScannerAnswer;
    }
    //Scan Error
    else if ( Response.find("241", 0, 3) == 0 )
    {
        ScannerAnswer = "2" + Response;
        return ScannerAnswer;
    }
    //Other Error
    else if ( Response.find("5", 0, 1) == 0 )
    {
        ScannerAnswer = "2" + Response;
        return ScannerAnswer;
    }
    //Other non-fatal responses
    else if ( Response.find("2", 0, 1) == 0 )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    LogFile::ErrorMessage("KAV: Unknown response from scanner: %s\n", Response.c_str());
    ScannerAnswer = "2Unknown scanner response";
    return ScannerAnswer;
}


void KasperskyScanner::FreeDatabase()
{
}

void KasperskyScanner::CloseSocket()
{
    AVESocket.Close();
    Connected = false;
}

//Constructor
KasperskyScanner::KasperskyScanner()
{
    ScannerName = "Kaspersky Socket Scanner";

    Connected = false;
    LastError = 0;

    ScannerAnswer.reserve(100);
}


//Destructor
KasperskyScanner::~KasperskyScanner()
{
}

