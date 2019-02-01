/***************************************************************************
                          avastscanner.cpp  -  description
                             -------------------
    begin                : Sa Feb 12 2005
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

#include "avastscanner.h"


bool AvastScanner::InitDatabase()
{
    return true;
}


int AvastScanner::ReloadDatabase()
{
    return 0;
}


string AvastScanner::Scan( const char *FileName )
{
    bool SockAnswer;

    if ( UseSocket )
    {
        SockAnswer = AvastSocket.ConnectToSocket( Params::GetConfigString("AVASTSOCKET"), 1 );
    }
    else
    {
        SockAnswer = AvastSocket.ConnectToServer();
    }

    if ( SockAnswer == false )
    {
        //Prevent log flooding, show error only once per minute
        if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
        {
            LogFile::ErrorMessage("Avast: Could not connect to scanner! Scanner down?\n");
            LastError = time(NULL);
        }

        ScannerAnswer = "2Could not connect to scanner socket";
        return ScannerAnswer;
    }

    //Construct command for scanner
    ScannerCmd = "SCAN ";
    ScannerCmd += FileName;
    ScannerCmd += "\r\nQUIT\r\n";

    //Send command
    if ( AvastSocket.Send( ScannerCmd ) == false )
    {
        AvastSocket.Close();

        //Try to reconnect after 1 second
        sleep(1);

        if ( UseSocket )
        {
            SockAnswer = AvastSocket.ConnectToSocket( Params::GetConfigString("AVASTSOCKET"), 1 );
        }
        else
        {
            SockAnswer = AvastSocket.ConnectToServer();
        }

        if ( SockAnswer == false )
        {
            //Prevent log flooding, show error only once per minute
            if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
            {
                LogFile::ErrorMessage("Avast: Could not connect to scanner! Scanner down?\n");
                LastError = time(NULL);
            }

            ScannerAnswer = "2Could not connect to scanner socket";
            return ScannerAnswer;
        }

        if ( AvastSocket.Send( ScannerCmd ) == false )
        {
            AvastSocket.Close();

            LogFile::ErrorMessage("Avast: Could not write command to scanner\n");
            ScannerAnswer = "2Scanner connection failed";
            return ScannerAnswer;
        }
    }

    string Response;
    Response.reserve(200);

    if ( AvastSocket.GetLine( Response, "\r\n", 600 ) == false )
    {
        AvastSocket.Close();

        ScannerAnswer = "2Could not read from scanner socket";
        return ScannerAnswer;
    }

    if ( MatchBegin( Response, "220", 3 ) == false )
    {
        AvastSocket.Close();

        LogFile::ErrorMessage("Avast: Invalid greeting from scanner\n");
        ScannerAnswer = "2Invalid greeting from scanner";
        return ScannerAnswer;
    }

    if ( AvastSocket.GetLine( Response, "\r\n", 600 ) == false )
    {
        AvastSocket.Close();

        ScannerAnswer = "2Could not read from scanner socket";
        return ScannerAnswer;
    }

    if ( MatchBegin( Response, "200 OK", 6 ) == false )
    {
        AvastSocket.Close();

        ScannerAnswer = "2" + Response;
        return ScannerAnswer;
    }

    ScannerAnswer = "";
    string::size_type Position;

    do
    {
        if ( AvastSocket.GetLine( Response, "\r\n", 600 ) == false )
        {
            AvastSocket.Close();

            ScannerAnswer = "2Could not read from scanner socket";
            return ScannerAnswer;
        }

        if ( (Position = Response.find("\t[L]\t")) != string::npos )
        {
            if ( (Position = Response.find_first_not_of("\t ", Position + 5)) != string::npos )
            {
                ScannerAnswer = "1" + Response.substr( Position );
                break;
            }
        }
    }
    while ( Response != "" && MatchBegin( Response, "221", 3 ) == false );
    
    //Connection will be closed
    AvastSocket.Close();

    //Clean?
    if ( ScannerAnswer == "" )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    //Virus?
    return ScannerAnswer;
}


void AvastScanner::FreeDatabase()
{
}


//Constructor
AvastScanner::AvastScanner()
{
    ScannerName = "Avast Socket Scanner";
    ScannerNameShort = "Avast";

    LastError = 0;

    if ( Params::GetConfigString("AVASTSERVER") != "" )
    {
        UseSocket = false;

        if ( AvastSocket.SetDomainAndPort( Params::GetConfigString("AVASTSERVER"), Params::GetConfigInt("AVASTPORT") ) == false )
        {
            LogFile::ErrorMessage("Avast: Could not resolve scanner host\n");
        }
    }
    else
    {
        UseSocket = true;
    }

    ScannerAnswer.reserve(100);
}


//Destructor
AvastScanner::~AvastScanner()
{
}

