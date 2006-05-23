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
    if ( Response.find("200", 0, 3) == string::npos )
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

        //Connect again
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

        //Get initial response
        if ( NOD32Socket.GetLine( Response, "\n\n", 600 ) == false )
        {
            NOD32Socket.Close();

            ScannerAnswer = "2Could not read from scanner socket";
            return ScannerAnswer;
        }

        //Check greeting
        if ( Response.find("200", 0, 3) == string::npos )
        {
            NOD32Socket.Close();

            LogFile::ErrorMessage("NOD32: Invalid greeting from scanner\n");
            ScannerAnswer = "2Invalid greeting from scanner";
            return ScannerAnswer;
        }

        ScannerCmd = "HELO\n" + Agent + "\nhavp\n\nPSET\nscan_obj_files = yes\nscan_obj_archives = yes\nscan_obj_emails = yes\nscan_obj_sfx = yes\nscan_obj_runtimepackers = yes\nscan_app_adware = yes\nscan_app_unsafe = yes\nscan_pattern = yes\nscan_heur = yes\nscan_adv_heur = yes\nscan_all_files = yes\naction_on_infected = \"reject\"\naction_on_notscanned = \"reject\"\nquarantine = no\ntmp_dir = \"";
        ScannerCmd += Params::GetConfigString("TEMPDIR") + "\"\n\n";

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
    }

    if ( NOD32Socket.GetLine( Response, "\n\n", 600 ) == false )
    {
        NOD32Socket.Close();

        LogFile::ErrorMessage("NOD32: Could not write command to scanner\n");
        ScannerAnswer = "2Scanner connection failed";
        return ScannerAnswer;
    }

    if ( Response.find("200 OK PSET", 0, 11) == string::npos )
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
    if ( Response.find("201 CLEAN", 0, 9) == 0 )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    //Infected
    if ( Response.find("501 INFECTED", 0, 12) == 0 )
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
    if ( Response.find("5", 0, 1) == 0 )
    {
        ScannerAnswer = "2" + Response;
        return ScannerAnswer;
    }

    LogFile::ErrorMessage("NOD32: Unknown response from scanner: %s\n", Response.c_str());
    ScannerAnswer = "2Unknown scanner response";
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

    //Assume we have NOD32 for Linux Mail Server by default
    Agent = "cli";

    ScannerAnswer.reserve(100);
}


//Destructor
NOD32Scanner::~NOD32Scanner()
{
}

