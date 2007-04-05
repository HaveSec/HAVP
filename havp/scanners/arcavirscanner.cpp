/***************************************************************************
                          arcavirscanner.cpp  -  description
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

#include "arcavirscanner.h"


bool ArcavirScanner::InitDatabase()
{
    return true;
}


int ArcavirScanner::ReloadDatabase()
{
    return 0;
}

string ArcavirScanner::Scan( const char *FileName )
{
    //Connect
    if ( ArcavirSocket.ConnectToSocket( Params::GetConfigString("ARCAVIRSOCKET"), 1 ) == false )
    {
        //Prevent log flooding, show error only once per minute
        if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
        {
            LogFile::ErrorMessage("Arcavir: Could not connect to scanner! Scanner down?\n");
            LastError = time(NULL);
        }

        ScannerAnswer = "2Could not connect to scanner socket";
        return ScannerAnswer;
    }

    //Scan command
    string ScannerCmd = "S ";
    ScannerCmd += FileName;
    ScannerCmd += "\n";

    //Send command
    if ( ArcavirSocket.Send( ScannerCmd ) == false )
    {
        ArcavirSocket.Close();

        LogFile::ErrorMessage("Arcavir: Could not write command to scanner\n");
        ScannerAnswer = "2Scanner connection failed";
        return ScannerAnswer;
    }

    string Response;

    if ( ArcavirSocket.GetLine( Response, "\n", 600 ) == false )
    {
        ArcavirSocket.Close();
        LogFile::ErrorMessage("Arcavir: Could not read scanner response\n");
        ScannerAnswer = "2Could not read scanner response";
        return ScannerAnswer;
    }

    ArcavirSocket.Close();

    //Clean
    if ( MatchBegin( Response, "OK", 2 ) )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    //Infected
    if ( MatchBegin( Response, "VIR", 3 ) )
    {
        ScannerAnswer = "1" + Response.substr( 4, Response.find( " ", 4 ) - 4 );
        return ScannerAnswer;
    }

    //Error
    if ( MatchBegin( Response, "ERR", 3 ) )
    {
        ScannerAnswer = "2" + Response.substr( 4, Response.find( " ", 4 ) - 4 );
        return ScannerAnswer;
    }

    LogFile::ErrorMessage("Arcavir: Unknown response from scanner: %s\n", Response.c_str());
    ScannerAnswer = "2Unknown scanner response";
    return ScannerAnswer;
}


void ArcavirScanner::FreeDatabase()
{
}


//Constructor
ArcavirScanner::ArcavirScanner()
{
    ScannerName = "Arcavir Socket Scanner";
    ScannerNameShort = "Arcavir";

    LastError = 0;

    ScannerAnswer.reserve(100);
}


//Destructor
ArcavirScanner::~ArcavirScanner()
{
}

