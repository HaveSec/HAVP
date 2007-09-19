/***************************************************************************
                          f-protscanner.cpp  -  description
                             -------------------
    begin                : Mit Jun 29 2005
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

#include "f-protscanner.h"


bool FProtScanner::InitDatabase()
{
    return true;
}
int FProtScanner::ReloadDatabase()
{
    return 0;
}
void FProtScanner::FreeDatabase()
{
}


string FProtScanner::Scan( const char *FileName )
{
    if ( Connected == false && ConnectScanner() == false )
    {
        ScannerAnswer = "2Could not connect to scanner";
        return ScannerAnswer;
    }

    if ( Version == 0 )
    {
        Version = TestVersion();

        if ( Version == 0 )
        {
            ScannerAnswer = "2Could not connect to scanner";
            return ScannerAnswer;
        }

        if ( Connected == false && ConnectScanner() == false )
        {
            ScannerAnswer = "2Could not connect to scanner";
            return ScannerAnswer;
        }
    }

    if ( Version == 6 ) return ScanV6( FileName );

    return ScanV4( FileName );
}


string FProtScanner::ScanV6( const char *FileName )
{
    //Construct command for scanner
    ScannerCmd = "SCAN ";
    ScannerCmd += Opts;
    ScannerCmd += "FILE ";
    ScannerCmd += FileName;
    ScannerCmd += "\n";

    if ( Scanner.Send( ScannerCmd ) == false )
    {
        Scanner.Close();
        Connected = false;

        LogFile::ErrorMessage("%s: Could not call scanner\n", ScannerNameShort.c_str());
        ScannerAnswer = "2Could not call scanner";
        return ScannerAnswer;
    }

    string Response;

    if ( Scanner.GetLine( Response, "\n", 600 ) == false )
    {
        Scanner.Close();
        Connected = false;

        LogFile::ErrorMessage("%s: Could not read scanner response\n", ScannerNameShort.c_str());
        ScannerAnswer = "2Could not read scanner response";
        return ScannerAnswer;
    }

    if ( MatchBegin( Response, "0 ", 2 ) )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    int status = 0;
    if ( sscanf(Response.substr(0,4).c_str(), "%d ", &status) != 1 ) status = 0;

    if ( status & 1 ||
         MatchBegin( Response, "1 ", 2 ) ||
         Response.find("<unwanted") != string::npos )
    {
        string VirusName = "unknown";

        string::size_type PosEnd = Response.find( ">" );

        if ( PosEnd != string::npos && PosEnd > 3 )
        {
            VirusName = Response.substr( 3, PosEnd - 3 );
        }

        SearchReplace( VirusName, "contains infected objects: ", "" );
        SearchReplace( VirusName, "infected: ", "" );

        //Reports "clean" for broken ZIPs with viruses?
        //Sadly it is the case when MAXSCANSIZE it reached too..
        if ( VirusName == "clean" ) VirusName = "virus inside archive";

        ScannerAnswer = "1" + VirusName;
        return ScannerAnswer;
    }

    //Code 2 for archive bombs etc
    //Different codes for encrypted files etc, but they are reported "clean"
    if ( MatchBegin( Response, "2 ", 2 ) ||
         Response.find("<clean>") != string::npos )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    LogFile::ErrorMessage("%s: Error response: %s\n", ScannerNameShort.c_str(), Response.c_str());
    ScannerAnswer = "2Scanner error";
    return ScannerAnswer;
}

string FProtScanner::ScanV4( const char *FileName )
{
    //Construct command for scanner
    ScannerCmd = "GET ";
    ScannerCmd += FileName;
    ScannerCmd += " HTTP/1.0\r\n\r\n";

    if ( Scanner.Send( ScannerCmd ) == false )
    {
        Scanner.Close();
        Connected = false;

        LogFile::ErrorMessage("%s: Could not call scanner\n", ScannerNameShort.c_str());
        ScannerAnswer = "2Could not call scanner";
        return ScannerAnswer;
    }

    string Response;
    int ret;

    while ( (ret = Scanner.Recv( Response, true, 600 )) != 0 )
    {
        if ( ret < 0 )
        {
            Scanner.Close();
            Connected = false;

            LogFile::ErrorMessage("%s: Could not read scanner response\n", ScannerNameShort.c_str());
            ScannerAnswer = "2Could not read scanner response";
            return ScannerAnswer;
        }
    }

    Scanner.Close();
    Connected = false;

    string::size_type PositionEnd;

    if ( (PositionEnd = Response.rfind( "</summary>", string::npos )) == string::npos )
    {
        LogFile::ErrorMessage("%s: Invalid response from scanner\n", ScannerNameShort.c_str());
        ScannerAnswer = "2Invalid response from scanner";
        return ScannerAnswer;
    }

    string::size_type Position;

    if ( (Position = Response.rfind( ">", PositionEnd )) == string::npos )
    {
        LogFile::ErrorMessage("%s: Invalid response from scanner\n", ScannerNameShort.c_str());
        ScannerAnswer = "2Invalid response from scanner";
        return ScannerAnswer;
    }

    string SummaryCode = Response.substr( Position + 1, PositionEnd - (Position + 1) );

    if ( SummaryCode == "clean" )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }
    else if ( SummaryCode == "infected" )
    {
        if ( (PositionEnd = Response.rfind( "</name>" )) != string::npos )
        {
            if ( (Position = Response.rfind( ">", PositionEnd )) == string::npos )
            {
                ScannerAnswer = "1Unknown";
                return ScannerAnswer;
            }

            ScannerAnswer = "1" + Response.substr( Position+1, PositionEnd - (Position + 1) );
            return ScannerAnswer;
        }
        else if ( (PositionEnd = Response.rfind( "</message>" )) != string::npos )
        {
            if ( (Position = Response.rfind( ">", PositionEnd )) == string::npos )
            {
                ScannerAnswer = "1Unknown";
                return ScannerAnswer;
            }

            ScannerAnswer = "1" + Response.substr( Position+1, PositionEnd - (Position + 1) );
            return ScannerAnswer;
        }
        else
        {
            ScannerAnswer = "1Unknown";
            return ScannerAnswer;
        }
    }

    ScannerAnswer = "2Unknown response from scanner";
    return ScannerAnswer;
}


int FProtScanner::TestVersion()
{
    //Construct command for scanner
    ScannerCmd = "HELP\nQUIT\n";

    if ( Scanner.Send( ScannerCmd ) == false )
    {
        Scanner.Close();
        Connected = false;

        LogFile::ErrorMessage("%s: Could not call scanner\n", ScannerNameShort.c_str());
        return 0;
    }

    string Response;
    int ret = Scanner.Recv( Response, true, 30 );

    Scanner.Close();
    Connected = false;

    if ( ret < 0 )
    {
        LogFile::ErrorMessage("%s: Could not read scanner response\n", ScannerNameShort.c_str());
        return 0;
    }

    if ( MatchBegin( Response, "FPSCAND:6", 9 ) )
    {
        return 6;
    }
    
    return 4;
}


bool FProtScanner::ConnectScanner()
{
    if ( Version == 4 )
    {
        if ( Scanner.SetDomainAndPort( ServerHost, ServerPort ) == false )
        {
            LogFile::ErrorMessage("%s: Could not resolve scanner host", ScannerNameShort.c_str());
            return false;
        }
    }

    if ( Scanner.ConnectToServer() == false )
    {
        if ( Version == 4 )
        {
            //Old F-Prot version might be updating, try next port..
            if ( Scanner.SetDomainAndPort( ServerHost, ServerPort + 1 ) == false )
            {
                LogFile::ErrorMessage("%s: Could not resolve scanner host", ScannerNameShort.c_str());
                return false;
            }
        }
        else
        {
            sleep(1);
        }

        if ( Scanner.ConnectToServer() == false )
        {
            Scanner.Close();
            Connected = false;

            //Prevent log flooding, show error only once per minute
            if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
            {
                LogFile::ErrorMessage("%s: Could not connect to scanner! Scanner down?\n", ScannerNameShort.c_str());
                LastError = time(NULL);
            }

            return false;
        }
    }

    Connected = true;
    return true;
}


//Close persistent connection from HAVP scanner initialization
//Needed because it will fork later
void FProtScanner::CloseSocket()
{
    Scanner.Close();
    Connected = false;
}


//Constructor
FProtScanner::FProtScanner()
{
    ScannerName = "F-Prot Socket Scanner";
    ScannerNameShort = "F-Prot";

    LastError = 0;
    Version = 0;
    Connected = false;

    ServerHost = Params::GetConfigString("FPROTSERVER");
    ServerPort = Params::GetConfigInt("FPROTPORT");
    Version = Params::GetConfigInt("FPROTVERSION");

    Opts = "";
    if ( Params::GetConfigString("FPROTOPTIONS") != "" )
    {
        Opts = Params::GetConfigString("FPROTOPTIONS") + " ";
    }

    if ( Scanner.SetDomainAndPort( ServerHost, ServerPort ) == false )
    {
        LogFile::ErrorMessage("%s: Could not resolve scanner host", ScannerNameShort.c_str());
    }

    ScannerAnswer.reserve(100);
}


//Destructor
FProtScanner::~FProtScanner()
{
}

