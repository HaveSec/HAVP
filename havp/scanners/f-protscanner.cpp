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


string FProtScanner::Scan( const char *FileName )
{
    if ( FProtSocket.SetDomainAndPort( ServerHost, ServerPort ) == false )
    {
        LogFile::ErrorMessage("F-Prot: Could not connect to scanner\n");
        ScannerAnswer = "2Could not connect to scanner";
        return ScannerAnswer;
    }

    if ( FProtSocket.ConnectToServer() == false )
    {
        //Could not connect? Maybe F-Prot is updating, try next port
        if ( FProtSocket.SetDomainAndPort( ServerHost, ServerPort + 1 ) == false )
        {
            LogFile::ErrorMessage("F-Prot: Could not connect to scanner\n");
            ScannerAnswer = "2Could not connect to scanner";
            return ScannerAnswer;
        }
        if ( FProtSocket.ConnectToServer() == false )
        {
            FProtSocket.Close();

            //Prevent log flooding, show error only once per minute
            if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
            {
                LogFile::ErrorMessage("F-Prot: Could not connect to scanner! Scanner down?\n");
                LastError = time(NULL);
            }

            ScannerAnswer = "2Could not connect to scanner";
            return ScannerAnswer;
        }
    }

    //Construct command for scanner
    ScannerCmd = "GET ";
    ScannerCmd += FileName;
    ScannerCmd += " HTTP/1.0\r\n\r\n";

    if ( FProtSocket.Send( ScannerCmd ) == false )
    {
        FProtSocket.Close();
        LogFile::ErrorMessage("F-Prot: Could not call scanner\n");
        ScannerAnswer = "2Could not call scanner";
        return ScannerAnswer;
    }

    string Response;
    int ret;

    while ( (ret = FProtSocket.Recv( Response, true, 600 )) != 0 )
    {
        if ( ret < 0 )
        {
            FProtSocket.Close();
            LogFile::ErrorMessage("F-Prot: Could not read scanner response\n");
            ScannerAnswer = "2Could not read scanner response";
            return ScannerAnswer;
        }
    }

    FProtSocket.Close();

    string::size_type PositionEnd;

    if ( (PositionEnd = Response.rfind( "</summary>", string::npos )) == string::npos )
    {
        LogFile::ErrorMessage("F-Prot: Invalid response from scanner\n");
        ScannerAnswer = "2Invalid response from scanner";
        return ScannerAnswer;
    }

    string::size_type Position;

    if ( (Position = Response.rfind( ">", PositionEnd )) == string::npos )
    {
        LogFile::ErrorMessage("F-Prot: Invalid response from scanner\n");
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


void FProtScanner::FreeDatabase()
{
}


//Constructor
FProtScanner::FProtScanner()
{
    ScannerName = "F-Prot Socket Scanner";
    ScannerNameShort = "F-Prot";

    LastError = 0;

    ServerHost = Params::GetConfigString("FPROTSERVER");
    ServerPort = Params::GetConfigInt("FPROTPORT");

    ScannerAnswer.reserve(100);
}


//Destructor
FProtScanner::~FProtScanner()
{
}

