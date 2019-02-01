/***************************************************************************
                          arcavirscanner.cpp  -  description
                             -------------------
    begin                : Sa Feb 12 2005
    copyright            : (C) 2005 by Christian Hilgers
    email                : christian@havp.org

 Help for Version 2008 received from Anthony Have (a.have@sysun-technologies.com)

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
    if ( Connected == false && ConnectScanner() == false )
    {
        ScannerAnswer = "2Could not connect to scanner";
        return ScannerAnswer;
    }

    if ( Version == 2008 ) return ScanV2008( FileName );

    return ScanV2007( FileName );
}

string ArcavirScanner::ScanV2008( const char *FileName )
{
    //Scan command
    string ScannerCmd = "SCAN ";
    ScannerCmd += FileName;
    ScannerCmd += "\n";

    //Send command
    if ( Scanner.Send( ScannerCmd ) == false )
    {
        Scanner.Close();

        //Retry one time
        if ( ConnectScanner() == false || Scanner.Send( ScannerCmd ) == false )
        {
            Scanner.Close();
            Connected = false;
            LogFile::ErrorMessage("Arcavir: Could not write command to scanner\n");
            ScannerAnswer = "2Scanner connection failed";
            return ScannerAnswer;
        }
    }

    string Response;
    string VirusName = "";

    do
    {
        if ( Scanner.GetLine( Response, "\n", 600 ) == false )
        {
            Scanner.Close();
            Connected = false;
            LogFile::ErrorMessage("Arcavir: Could not read scanner response\n");
            ScannerAnswer = "2Could not read scanner response";
            return ScannerAnswer;
        }

        if ( VirusName != "" ) continue;

        if ( MatchSubstr( Response, " ERROR", -1 ) )
        {
            Scanner.Close();
            Connected = false;
            LogFile::ErrorMessage("Arcavir: %s\n", Response.substr( Response.find(": ") + 2 ).c_str() );
            ScannerAnswer = "2Scanner error";
            return ScannerAnswer;
        }

        if ( MatchSubstr( Response, " FOUND", -1 ) )
        {
            string::size_type Position = Response.find(": ") + 2;
            string::size_type PositionEnd = Response.find(" ", Position);
            VirusName = Response.substr( Position, PositionEnd - Position );
        }
    }
    while ( Response != "" && !MatchSubstr( Response, " END", -1 ) );

    if ( VirusName != "" )
    {
        ScannerAnswer = "1" + VirusName;
        return ScannerAnswer;
    }

    ScannerAnswer = "0Clean";
    return ScannerAnswer;
}


string ArcavirScanner::ScanV2007( const char *FileName )
{
    //Scan command
    string ScannerCmd = "S ";
    ScannerCmd += FileName;
    ScannerCmd += "\n";

    //Send command
    if ( Scanner.Send( ScannerCmd ) == false )
    {
        Scanner.Close();
        Connected = false;

        LogFile::ErrorMessage("Arcavir: Could not write command to scanner\n");
        ScannerAnswer = "2Scanner connection failed";
        return ScannerAnswer;
    }

    string Response;

    if ( Scanner.GetLine( Response, "\n", 600 ) == false )
    {
        Scanner.Close();
        Connected = false;
        LogFile::ErrorMessage("Arcavir: Could not read scanner response\n");
        ScannerAnswer = "2Could not read scanner response";
        return ScannerAnswer;
    }

    Scanner.Close();
    Connected = false;

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

bool ArcavirScanner::ConnectScanner()
{
    //Connect
    if ( Scanner.ConnectToSocket( Params::GetConfigString("ARCAVIRSOCKET"), 1 ) == false )
    {
        //Prevent log flooding, show error only once per minute
        if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
        {
            LogFile::ErrorMessage("Arcavir: Could not connect to scanner! Scanner down?\n");
            LastError = time(NULL);
        }

        return false;
    }

    if ( Version == 2008 )
    {
        //Persistent connection for version 2008+
        string ScannerCmd = "SESSION\n";

        //Send command
        if ( Scanner.Send( ScannerCmd ) == false )
        {
            Scanner.Close();
            LogFile::ErrorMessage("Arcavir: Could not write command to scanner\n");
            return false;
        }
    }
    
    Connected = true;
    return true;
}

void ArcavirScanner::FreeDatabase()
{
}

//Close persistent connection from HAVP scanner initialization
//Needed because it will fork later
void ArcavirScanner::CloseSocket()
{
    Scanner.Close();
    Connected = false;
}


//Constructor
ArcavirScanner::ArcavirScanner()
{
    ScannerName = "Arcavir Socket Scanner";
    ScannerNameShort = "Arcavir";

    Connected = false;

    Version = Params::GetConfigInt("ARCAVIRVERSION");

    LastError = 0;

    ScannerAnswer.reserve(100);
}


//Destructor
ArcavirScanner::~ArcavirScanner()
{
}

