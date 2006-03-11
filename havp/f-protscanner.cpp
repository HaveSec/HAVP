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
#include "sockethandler.h"


//Init F-Port - it's a socket so nothing to do here
bool FProtScanner::InitDatabase()
{
    return true;
}

//Reload scanner engine - it's a socket so nothing to do here
bool  FProtScanner::ReloadDatabase()
{
    return false;
}

//Start scan
int FProtScanner::Scanning()
{

    char Ready[2];
    int fd;
    ScannerAnswer = "";

    if ( (fd = open(FileName, O_RDONLY)) < 0 )
    {
        LogFile::ErrorMessage("Could not open file to scan: %s\n", FileName);
        ScannerAnswer="Could not open file to scan";

        close(fd);
        return 2;
    }

    //Wait till file is set up for scanning
    while (read(fd, Ready, 1) < 0 && errno == EINTR);
    close(fd);

    string fprotserver = Params::GetConfigString("FPROTSERVER");
    int fprotport = Params::GetConfigInt("FPROTPORT");

    if ( FProtSocket.SetDomainAndPort( fprotserver, fprotport ) == false )
    {
        LogFile::ErrorMessage("Could not connect to scanner\n");
        ScannerAnswer = "Could not connect to scanner";
        return 2;
    }

    if ( FProtSocket.ConnectToServer() == false )
    {
        //Could not connect? Maybe F-Prot is updating, try next port
        if ( FProtSocket.SetDomainAndPort( fprotserver, fprotport + 1 ) == false )
        {
            LogFile::ErrorMessage("Could not connect to scanner\n");
            ScannerAnswer = "Could not connect to scanner";
            return 2;
        }
        if ( FProtSocket.ConnectToServer() == false )
        {
            FProtSocket.Close();
            LogFile::ErrorMessage("Could not connect to scanner\n");
            ScannerAnswer = "Could not connect to scanner";
            return 2;
        }
    }

    //Construct command for scanner
    string ScannerCmd = "GET ";
    ScannerCmd += FileName;
    ScannerCmd += " HTTP/1.0\r\n\r\n";

    if ( FProtSocket.Send ( &ScannerCmd ) == false )
    {
        FProtSocket.Close();
        LogFile::ErrorMessage("Could not call scanner\n");
        ScannerAnswer = "Could not call scanner";
        return 2;
    }

    string Response;
    int ret;

    while ( (ret = FProtSocket.Recv( &Response, true )) != 0 )
    {
        if ( ret < 0 )
        {
            FProtSocket.Close();
            LogFile::ErrorMessage("Could not read scanner response\n");
            ScannerAnswer = "Could not read scanner response";
            return 2;
        }
    }

    FProtSocket.Close();

    string::size_type PositionEnd;

    if ( (PositionEnd = Response.rfind( "</summary>", string::npos )) == string::npos )
    {
        LogFile::ErrorMessage("Invalid response from scanner\n");
        ScannerAnswer = "Invalid response from scanner";
        return 2;
    }

    string::size_type Position;

    if ( (Position = Response.rfind( ">", PositionEnd )) == string::npos )
    {
        LogFile::ErrorMessage("Invalid response from scanner\n");
        ScannerAnswer = "Invalid response from scanner";
        return 2;
    }

    string SummaryCode = Response.substr( Position + 1, PositionEnd - (Position + 1) );

    if ( SummaryCode == "clean" )
    {
        ScannerAnswer = "Clean";
        return 0;
    }
    else if ( SummaryCode == "infected" )
    {
        if ( (PositionEnd = Response.rfind( "</name>" )) == string::npos )
        {
            ScannerAnswer="unknown";
            return 1;
        }

        if ( (Position = Response.rfind( ">", PositionEnd )) == string::npos )
        {
            ScannerAnswer="unknown";
            return 1;
        }

        ScannerAnswer = Response.substr( Position+1, PositionEnd - (Position + 1) );
        return 1;
    }

    ScannerAnswer = "Unknown response from scanner";
    return 2;
}

void FProtScanner::FreeDatabase()
{
}

FProtScanner::FProtScanner(){
}
FProtScanner::~FProtScanner(){
}
