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
bool FProtScanner::InitDatabase(){
return true;
}

//Reload scanner engine - it's a socket so nothing to do here
bool  FProtScanner::ReloadDatabase()
{
return true;
}

//Init scanning engine - do filelock and so on
bool FProtScanner::InitSelfEngine()
{

    if( OpenAndLockFile() == false)
    {
        return false;
    }

    return true;
}


int FProtScanner::ScanningComplete()
{

    int status=0;

    UnlockFile();

    //Wait till scanning is complete
    waitpid( ScannerPid, &status, 0);

    //Delete scanned file
    DeleteFile();

    //Virus found ? 0=No ; -1=Yes; -2=Scanfail
    return WEXITSTATUS(status);

}


//Start scan
int FProtScanner::Scanning( )
{

 string ScannerRequest = "GET ";
 string FProtAnswer="";
 int AnswerStatus;
 char Ready[10];

 int fd;

 string SummaryCode;

 string::size_type FinderStart;
 string::size_type FinderEnd;

 ScannerRequest += FileName;

// ScannerRequest += FPROTOPTIONS;
 ScannerRequest += " HTTP/1.0\r\n\r\n";

 SocketHandler FProtSocket;

 if ( (fd = open(FileName, O_RDONLY)) < 0)
 {
    LogFile::ErrorMessage ("Could not open file to scan: %s\n", FileName );
    ScannerAnswer="Could not open file to scan";
    	WriteScannerAnswer();
        close(fd);
        exit (2);
  }

 //Wait till file is set up for scanning
 read(fd, Ready, 1);
  close(fd);


string fprotserver = Params::GetConfigString("FPROTSERVER");
int fprotport = Params::GetConfigInt("FPROTPORT");

 FProtSocket.SetDomainAndPort( fprotserver.c_str() , fprotport );

 if( FProtSocket.ConnectToServer( ) == false ){
   ScannerAnswer="Could not connect to F-Prot Server";
   LogFile::ErrorMessage ("%s\n", ScannerAnswer.c_str() );
   WriteScannerAnswer();
   exit (2);
 }


 if( FProtSocket.Send ( &ScannerRequest ) == false ){
   ScannerAnswer="Could not send Request to F-Prot Server";
   LogFile::ErrorMessage ("%s\n", ScannerAnswer.c_str() );
   WriteScannerAnswer();
   exit (2);
  }

  while( (AnswerStatus = FProtSocket.Recv( &FProtAnswer, true )) != 0 ){

    if( AnswerStatus == -1 )
    {
      ScannerAnswer="Could not receive data completly form F-Prot Server";
      LogFile::ErrorMessage ("%s\n", ScannerAnswer.c_str() );
      WriteScannerAnswer();
      exit (2);
    }

  }

  //Check if there was a virus

  //Check first if we got the summary code
  if ( (FinderEnd =  FProtAnswer.rfind ( "</summary>" )) == string::npos ){
      ScannerAnswer="F-Prot Server delivers invalid answer";
      LogFile::ErrorMessage ("%s\n", ScannerAnswer.c_str() );
      WriteScannerAnswer();
      exit (2);
  }

  if ( (FinderStart =  FProtAnswer.rfind ( ">", FinderEnd )) == string::npos ){
      ScannerAnswer="F-Prot Server delivers invalid answer";
      LogFile::ErrorMessage ("%s\n", ScannerAnswer.c_str() );
      WriteScannerAnswer();
      exit (2);
  }

  SummaryCode = FProtAnswer.substr( FinderStart+1, FinderEnd - (FinderStart + 1) );


  if ( SummaryCode == "infected" ){

   if ( (FinderEnd =  FProtAnswer.rfind ( "</name>" )) == string::npos ){
      ScannerAnswer="infected by unknown";
      LogFile::ErrorMessage ("%s\n", ScannerAnswer.c_str() );
      WriteScannerAnswer();
      exit (1);
   }

   if ( (FinderStart =  FProtAnswer.rfind ( ">", FinderEnd )) == string::npos ){
      ScannerAnswer="infected by unknown";
      LogFile::ErrorMessage ("%s\n", ScannerAnswer.c_str() );
      WriteScannerAnswer();
      exit (1);
   }

   ScannerAnswer = FProtAnswer.substr( FinderStart+1, FinderEnd - (FinderStart + 1) );

   LogFile::ErrorMessage ("Virus Found: %s\n", ScannerAnswer.c_str() );
   WriteScannerAnswer();
   exit (1);

  } else if ( SummaryCode == "clean" ){
    ScannerAnswer=SummaryCode;
    WriteScannerAnswer();
    exit (0);

  } else {

   LogFile::ErrorMessage ("Unknown: %s\n", SummaryCode.c_str() );
   WriteScannerAnswer();
   exit (2);

  }


return 0;
}


FProtScanner::FProtScanner(){
}
FProtScanner::~FProtScanner(){
}
