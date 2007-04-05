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


int KasperskyScanner::ReloadDatabase()
{
    return 0;
}


string KasperskyScanner::Scan( const char *FileName )
{
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
        if ( AVESocket.GetLine( Response, "\r\n", 600 ) == false )
        {
            AVESocket.Close();

            ScannerAnswer = "2Could not read from scanner socket";
            return ScannerAnswer;
        }

        //Check greeting
        if ( MatchBegin( Response, "201", 3 ) == false )
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
    if ( AVESocket.Send( ScannerCmd ) == false )
    {
        AVESocket.Close();
        Connected = false;

        //Try to reconnect if failed
        sleep(1);

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
        if ( AVESocket.GetLine( Response, "\r\n", 600 ) == false )
        {
            AVESocket.Close();

            ScannerAnswer = "2Could not read from scanner socket";
            return ScannerAnswer;
        }

        //Check greeting
        if ( MatchBegin( Response, "201", 3 ) == false )
        {
            AVESocket.Close();

            LogFile::ErrorMessage("KAV: Invalid greeting from scanner\n");
            ScannerAnswer = "2Invalid greeting from scanner";
            return ScannerAnswer;
        }

        //Send command.. again
        if ( AVESocket.Send( ScannerCmd ) == false )
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
        if ( AVESocket.GetLine( Response, "\r\n", 600 ) == false )
        {
            AVESocket.Close();
            Connected = false;

            ScannerAnswer = "2Could not read from scanner socket";
            return ScannerAnswer;
        }

        //Virus name found
        if ( MatchBegin( Response, "322-", 4 ) )
        {
            string::size_type Position;

            if ( (Position = Response.find("/", 4)) != string::npos )
            {
                ScannerAnswer = "1" + Response.substr( 4, Position - 5 );
            }
        }
    }
    while ( MatchBegin( Response, "3", 1 ) );

    //Clean
    if ( MatchBegin( Response, "220", 3 ) )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }
    //Infected
    else if ( MatchBegin( Response, "230", 3 ) )
    {
        if (ScannerAnswer == "") ScannerAnswer = "1Unknown";
        return ScannerAnswer;
    }
    //Suspicious
    else if ( MatchBegin( Response, "232", 3 ) )
    {
        if (ScannerAnswer == "") ScannerAnswer = "1Suspicious";
        return ScannerAnswer;
    }
    //Scan Error
    else if ( MatchBegin( Response, "241", 3 ) )
    {
        ScannerAnswer = "2" + Response;
        return ScannerAnswer;
    }
    //Other Error
    else if ( MatchBegin( Response, "5", 1 ) )
    {
        ScannerAnswer = "2" + Response;
        return ScannerAnswer;
    }
    //Other non-fatal responses
    else if ( MatchBegin( Response, "2", 1 ) )
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
    ScannerNameShort = "KAV";

    Connected = false;
    LastError = 0;

    ScannerAnswer.reserve(100);
}


//Destructor
KasperskyScanner::~KasperskyScanner()
{
}

