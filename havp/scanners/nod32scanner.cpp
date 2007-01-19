/***************************************************************************
                          nod32scanner.cpp  -  description
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

#include "nod32scanner.h"


bool NOD32Scanner::InitDatabase()
{
    return true;
}


bool NOD32Scanner::ReloadDatabase()
{
    return false;
}

string NOD32Scanner::Scan( const char *FileName )
{
    if ( Version == 25 )
    {
        return ScanV25( FileName );
    }

    return ScanV21( FileName );
}

string NOD32Scanner::ScanV25( const char *FileName )
{
    //Connect
    if ( NOD32Socket.ConnectToSocket( Params::GetConfigString("NOD32SOCKET"), 1 ) == false )
    {
        //Prevent log flooding, show error only once per minute
        if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
        {
            LogFile::ErrorMessage("NOD32: Could not connect to scanner! Scanner down?\n");
            LastError = time(NULL);
        }

        ScannerAnswer = "2Could not connect to scanner socket";
        return ScannerAnswer;
    }

    string Response;

    //Get initial response
    if ( NOD32Socket.GetLine( Response, "\n\n", 600 ) == false )
    {
        NOD32Socket.Close();

        ScannerAnswer = "2Could not read from scanner socket";
        return ScannerAnswer;
    }

    //Check greeting
    if ( MatchBegin( Response, "200", 3 ) == false )
    {
        NOD32Socket.Close();

        LogFile::ErrorMessage("NOD32: Invalid greeting from scanner\n");
        ScannerAnswer = "2Invalid greeting from scanner";
        return ScannerAnswer;
    }

    //Send HELO and PARAMS
    ScannerCmd = "HELO\n";
    ScannerCmd += Agent;
    ScannerCmd += "\nhavp\n\nPSET\nscan_obj_files = yes\nscan_obj_archives = yes\nscan_obj_emails = yes\nscan_obj_sfx = yes\nscan_obj_runtimepackers = yes\nscan_app_adware = yes\nscan_app_unsafe = yes\nscan_pattern = yes\nscan_heur = yes\nscan_adv_heur = yes\nscan_all_files = yes\naction_on_infected = \"reject\"\naction_on_notscanned = \"reject\"\nquarantine = no\ntmp_dir = \"";
    ScannerCmd += Params::GetConfigString("TEMPDIR");
    ScannerCmd += "\"\n\n";

    //Send command
    if ( NOD32Socket.Send( ScannerCmd ) == false )
    {
        NOD32Socket.Close();

        LogFile::ErrorMessage("NOD32: Could not write command to scanner\n");
        ScannerAnswer = "2Scanner connection failed";
        return ScannerAnswer;
    }

    //Receive responses
    NOD32Socket.GetLine( Response, "\n\n", 600 );

    //If we have NOD32 for Linux File Server, change Agent to pac
    //We can't get virusnames then :(
    if ( Agent == "cli" && Response == "401 Access denied for agent cli" )
    {
        LogFile::ErrorMessage("NOD32 for Linux File Server detected, virus names are not shown\n");
        Agent = "pac";

        NOD32Socket.Close();

        return Scan( FileName );
    }

    if ( NOD32Socket.GetLine( Response, "\n\n", 600 ) == false )
    {
        NOD32Socket.Close();

        LogFile::ErrorMessage("NOD32: Could not write command to scanner\n");
        ScannerAnswer = "2Scanner connection failed";
        return ScannerAnswer;
    }

    if ( MatchBegin( Response, "200 OK PSET", 11 ) == false )
    {
        NOD32Socket.Close();

        LogFile::ErrorMessage("NOD32: Invalid response from scanner: %s\n", Response.c_str());
        ScannerAnswer = "2Invalid response from scanner";
        return ScannerAnswer;
    }

    ScannerCmd = "SCAN\n";
    ScannerCmd += FileName;
    ScannerCmd += "\n\nQUIT\n\n";

    //Send command
    if ( NOD32Socket.Send( ScannerCmd ) == false )
    {
        NOD32Socket.Close();

        LogFile::ErrorMessage("NOD32: Could not write command to scanner\n");
        ScannerAnswer = "2Scanner connection failed";
        return ScannerAnswer;
    }

    Response = "";
    int ret;

    while ( (ret = NOD32Socket.Recv( Response, true, 600 )) != 0 )
    {
        if (ret < 0)
        {
            NOD32Socket.Close();
            LogFile::ErrorMessage("NOD32: Could not read scanner response\n");
            ScannerAnswer = "2Could not read scanner response";
            return ScannerAnswer;
        }
    }

    NOD32Socket.Close();

    //Clean
    if ( MatchBegin( Response, "201 CLEAN", 9 ) )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    //Infected
    if ( MatchBegin( Response, "501 INFECTED", 12 ) )
    {
        if ( Agent != "cli" )
        {
            ScannerAnswer = "1Unknown";
            return ScannerAnswer;
        }

        string::size_type Position;

        ScannerAnswer = "";

        if ( (Position = Response.find("||")) != string::npos )
        {
            string::size_type PositionEnd = Position - 1;

            if ( (Position = Response.rfind("|", PositionEnd)) != string::npos )
            {
                ScannerAnswer = "1" + Response.substr( Position + 1, PositionEnd - Position );
            }
        }

        if ( ScannerAnswer == "" ) ScannerAnswer = "1Unknown";
        return ScannerAnswer;
    }

    //Error
    if ( MatchBegin( Response, "5", 1 ) )
    {
        ScannerAnswer = "2" + Response;
        return ScannerAnswer;
    }

    LogFile::ErrorMessage("NOD32: Unknown response from scanner: %s\n", Response.c_str());
    ScannerAnswer = "2Unknown scanner response";
    return ScannerAnswer;
}


string NOD32Scanner::ScanV21( const char *FileName )
{
    //Connect
    if ( NOD32Socket.ConnectToSocket( Params::GetConfigString("NOD32SOCKET"), 1 ) == false )
    {
        //Prevent log flooding, show error only once per minute
        if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
        {
            LogFile::ErrorMessage("NOD32: Could not connect to scanner! Scanner down?\n");
            LastError = time(NULL);
        }

        ScannerAnswer = "2Could not connect to scanner socket";
        return ScannerAnswer;
    }

    string Response;

    //Get initial response
    if ( NOD32Socket.Recv( Response, true, 30 ) <= 0 )
    {
        NOD32Socket.Close();

        ScannerAnswer = "2Could not read from scanner socket";
        return ScannerAnswer;
    }

    //Check greeting
    if ( MatchBegin( Response, "200", 3 ) == false )
    {
        NOD32Socket.Close();

        LogFile::ErrorMessage("NOD32: Invalid greeting from scanner\n");
        ScannerAnswer = "2Invalid greeting from scanner";
        return ScannerAnswer;
    }

    //Send HELO and PARAMS
    char ScannerCmd[] = "SETU\0SCFI1\0SCAR1\0SCEM1\0SCRT1\0SCSX1\0SCAD1\0SCUS1\0EXSC0\0SCPA1\0SCHE1\0SCHS2\0WREM0\0WRSB0\0WRHD0\0ALLF1\0LOGA0\0ACTI0\0ACTU16\0SNDS0\0\0";

    //Send command - doublecheck lenght parameter..
    if ( NOD32Socket.Send( ScannerCmd, 121 ) == false )
    {
        NOD32Socket.Close();

        LogFile::ErrorMessage("NOD32: Could not write command to scanner\n");
        ScannerAnswer = "2Scanner connection failed";
        return ScannerAnswer;
    }

    //Receive response
    Response = "";
    if ( NOD32Socket.Recv( Response, true, 600 ) <= 0 )
    {
        NOD32Socket.Close();

        ScannerAnswer = "2Could not read from scanner socket";
        return ScannerAnswer;
    }

    if ( MatchBegin( Response, "200", 3 ) == false )
    {
        NOD32Socket.Close();

        LogFile::ErrorMessage("NOD32: Invalid response from scanner: %s\n", Response.c_str());
        ScannerAnswer = "2Invalid response from scanner";
        return ScannerAnswer;
    }

    //Blah..
    char ScanCmd[1024];
    ScanCmd[0] = '\0';
    strcat(ScanCmd, "SCAN*cli*");
    strncat(ScanCmd, FileName, 200);
    strcat(ScanCmd, "**QUIT*");
    int ScanLen = strlen(ScanCmd);
    for ( int j = 0; j <= ScanLen; j++ ) { if ( ScanCmd[j] == '*' ) ScanCmd[j] = '\0'; }

    //Send command
    if ( NOD32Socket.Send( ScanCmd, ScanLen + 1 ) == false )
    {
        NOD32Socket.Close();

        LogFile::ErrorMessage("NOD32: Could not write command to scanner\n");
        ScannerAnswer = "2Scanner connection failed";
        return ScannerAnswer;
    }

    Response = "";
    int ret;

    while ( (ret = NOD32Socket.Recv( Response, true, 600 )) != 0 )
    {
        if (ret < 0)
        {
            NOD32Socket.Close();
            LogFile::ErrorMessage("NOD32: Could not read scanner response\n");
            ScannerAnswer = "2Could not read scanner response";
            return ScannerAnswer;
        }
    }

    NOD32Socket.Close();

    //Clean or archive error
    if ( MatchBegin( Response, "200", 3 ) || MatchBegin( Response, "205", 3 ) )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    //Infected
    if ( MatchBegin( Response, "201", 3 ) )
    {
        ScannerAnswer = "1Unknown";
        return ScannerAnswer;
    }

    //Error
    ScannerAnswer = "2" + Response;
    return ScannerAnswer;
}


void NOD32Scanner::FreeDatabase()
{
}


//Constructor
NOD32Scanner::NOD32Scanner()
{
    ScannerName = "NOD32 Socket Scanner";
    ScannerNameShort = "NOD32";

    LastError = 0;

    //Assume we have NOD32 v2.5+ for Linux Mail Server by default
    Agent = "cli";
    Version = Params::GetConfigInt("NOD32VERSION");
    if ( Version != 25 && Version != 21 ) { Version = 25; }

    ScannerAnswer.reserve(100);
}


//Destructor
NOD32Scanner::~NOD32Scanner()
{
}

