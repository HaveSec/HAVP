/***************************************************************************
                          avgscanner.cpp  -  description
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

#include "avgscanner.h"


bool AVGScanner::InitDatabase()
{
    return true;
}


int AVGScanner::ReloadDatabase()
{
    return 0;
}


string AVGScanner::Scan( const char *FileName )
{
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

    string Response;
    AVGSocket.Recv( Response, true, 5 );

    if ( MatchSubstr( Response, "220 Ready", -1 ) == false )
    {
        AVGSocket.Close();
        LogFile::ErrorMessage("AVG: Invalid greeting from scanner (%s)\n", Response.c_str());
        ScannerAnswer = "2Invalid greeting from scanner";
        return ScannerAnswer;
    }

    //Construct command for scanner
    ScannerCmd = "SCAN ";
    ScannerCmd += FileName;
    ScannerCmd += "\r\n";

    if ( AVGSocket.Send( ScannerCmd ) == false )
    {
        AVGSocket.Close();
        LogFile::ErrorMessage("AVG: Could not connect to scanner\n");
        ScannerAnswer = "2Could not call scanner";
        return ScannerAnswer;
    }

    Response = "";
    int ret;

    ret = AVGSocket.Recv( Response, true, 600 );
    if (ret < 0)
    {
        AVGSocket.Close();
        LogFile::ErrorMessage("AVG: Could not read scanner response\n");
        ScannerAnswer = "2Could not read scanner response";
        return ScannerAnswer;
    }

    string Quit = "QUIT\r\n";
    AVGSocket.Send( Quit );
    AVGSocket.Recv( Quit, true, 2 );
    AVGSocket.Close();

    if ( Response.length() < 5 )
    {
        LogFile::ErrorMessage("AVG: Invalid response from scanner, report to developer (%s)\n", Response.c_str());
        ScannerAnswer = "2Invalid response from scanner";
        return ScannerAnswer;
    }

    if ( MatchSubstr( Response, "200 ok", -1 )
         || MatchSubstr( Response, "200 OK", -1 ) )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    string::size_type Position;

    if ( ( Position = Response.find( "403 File" )) != string::npos )
    {
        string::size_type PositionEnd, PositionStart;

        PositionEnd = Response.find("\n", Position + 10);
        PositionStart = Response.rfind(" ", PositionEnd - 3);
        string vname = Response.substr( PositionStart + 1, PositionEnd - PositionStart - 2);
        if (vname.rfind(" ") == vname.length() - 1) vname = vname.substr( 0, vname.length() - 1 );

        ScannerAnswer = "1" + vname;

        return ScannerAnswer;
    }

    //If AVG is reloading patterns, it will give error, just skip it
    if ( MatchSubstr( Response, "406 Error", -1 ) )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    // Log errors
    if ( MatchSubstr( Response, "local error", -1 ) )
    {
        LogFile::ErrorMessage("AVG: Scanner error: %s\n", Response.c_str());
        ScannerAnswer = "2Scanner error";
        return ScannerAnswer;
    }

    //LogFile::ErrorMessage("AVG: Unknown response from scanner, report to developer (%s)\n", Response.c_str());
    //ScannerAnswer = "2Unknown response from scanner: " + Response;
    //return ScannerAnswer;

    //Just return clean for anything else right now..
    ScannerAnswer = "0Clean";
    return ScannerAnswer;
}


void AVGScanner::FreeDatabase()
{
}


//Constructor
AVGScanner::AVGScanner()
{
    ScannerName = "AVG Socket Scanner";
    ScannerNameShort = "AVG";

    LastError = 0;

    if ( AVGSocket.SetDomainAndPort( Params::GetConfigString("AVGSERVER"), Params::GetConfigInt("AVGPORT") ) == false )
    {
        LogFile::ErrorMessage("AVG: Could not resolve scanner host\n");
    }

    ScannerAnswer.reserve(100);
}


//Destructor
AVGScanner::~AVGScanner()
{
}
