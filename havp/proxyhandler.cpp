/***************************************************************************
                          proxyhandler.cpp  -  description
                             -------------------
    begin                : So Feb 20 2005
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

#include "proxyhandler.h"

bool ProxyHandler::Proxy ( SocketHandler *ProxyServerT, GenericScanner *VirusScannerT)
{
int CommunicationAnswer;

 if ( (CommunicationAnswer = Communication ( ProxyServerT,  VirusScannerT )) != 0){
 
   ProxyMessage( CommunicationAnswer , VirusScannerT );

   ToBrowser.Close();
   ToServer.Close();
   return false;
   }

 LogFile::AccessMessage("%s %d OK\n", ToBrowser.Request.c_str(), Port);
   
 ToBrowser.Close();
 ToServer.Close();
   
 return true;
}


int ProxyHandler::Communication( SocketHandler *ProxyServerT, GenericScanner *VirusScannerT)
{

int TempScannerAnswer;

bool unlock = false;

string Header;
string Body;
string TempString;

Host="";

unsigned long ContentLengthReference = 0;
unsigned long ContentLength = 0;

ssize_t BodyLength = 0;

HeaderSend = false;

string TransferData = "";
string TransferToClient = "";


   if( ProxyServerT->AcceptClient( &ToBrowser ) == false)
   {
     LogFile::ErrorMessage("Could not accept browser\n");
    return -10;
   }

   if( ToBrowser.ReadHeader( &Header ) == false)
   {
     LogFile::ErrorMessage("Could not read header from browser\n");
    return -20;
   }

   if( ToBrowser.TokenizeHeader( &Header, "\n") == false)
   {
     LogFile::ErrorMessage("Could not torkenize header\n%s\n", Header.c_str());
    return -30;
   }


   if( ToBrowser.GetHostAndPort( &Host, &Port ) == false)
   {
     LogFile::ErrorMessage("Could not get host of header\n%s\n", Header.c_str());
     return -40;
   }

   if( ToServer.SetDomainAndPort( (char*)Host.c_str(), Port ) == false )
   {
     LogFile::ErrorMessage("Could not resolve hostname: %s\n", Host.c_str());
    return -50;
   }

   if( ToServer.ConnectToServer ( ) == false)
   {
     LogFile::ErrorMessage("Could not connect to server %s Port %d\n", Host.c_str(), Port);
    return -60;
   }

   Header = ToBrowser.PrepareHeaderForServer();

   ToServer.SendHeader(&Header);

   ContentLengthReference = ToBrowser.GetContentLength( );


  if (  ContentLengthReference != 0 ){
     //We expect POST data
     Body="";
     if ( ToBrowser.RecvLength( &Body, ContentLengthReference) == false )
     {
     LogFile::ErrorMessage("Could not read Browser Post: %s Port %d\n", ToBrowser.Request.c_str(), Port);
     return -70;
     }
     //IE Bug - send addtional \r\n
     if ( ToBrowser.CheckForData() == true )
     {
     ToBrowser.Recv( &TempString, false);
     if ( TempString == "\r\n" )
       {
        ToBrowser.RecvLength( &TempString, 2);
       }
     }
     ToServer.Send( &Body );
    }

   if ( ToServer.ReadHeader(&Header) == false){
     LogFile::ErrorMessage("Could not read Server Header: %s Port %d\n", ToBrowser.Request.c_str(), Port);
     return -80;
    }

   ToServer.TokenizeHeader( &Header, "\n");

   ContentLengthReference = ToServer.GetContentLength( );

   if ( ContentLengthReference > 0 )
   {
      unlock = true;
      //Set tempfile to right size
      if ( VirusScannerT->SetFileSize( ContentLengthReference ) == false )
      {
      LogFile::ErrorMessage("Could set file size: %s Port %d\n", ToBrowser.Request.c_str(), Port);
      return -90;
      }
   }
         
   Header = ToServer.PrepareHeaderForBrowser();
   
   //Transfer Body
   while ( (BodyLength = ToServer.ReadBodyPart(&Body)) != 0)
   {

   if( BodyLength == -1) {
     LogFile::ErrorMessage("Could not read Server Body: %s Port %d\n", ToBrowser.Request.c_str(), Port);
     return -100;
     }


     //Does Browser drop connection
     if(ToBrowser.IsConnectionDropped() == true )
     {
     LogFile::ErrorMessage("Browser dropped Connection: %s Port %d\n", ToBrowser.Request.c_str(), Port);
     return -110;
     }
     
     //Body size check
     ContentLength += BodyLength;
     if ( (unlock == true) && ( ContentLength > ContentLengthReference ) )
     {
     LogFile::ErrorMessage("ContentLength and Body size does not fit: %s Port %d\n", ToBrowser.Request.c_str(), Port);
     return -120;
     }
     
     //String add
     TransferData += Body;

     //Expand file to scan
     if ( VirusScannerT->ExpandFile( (char *)Body.c_str(), Body.length() , unlock ) == false ){
       LogFile::ErrorMessage("Could not expand tempfile: %s Port %d\n", ToBrowser.Request.c_str(), Port);
      return -130;
      }

   if ( TransferData.length() > KEEPBACKBUFFER ){
  
   //This check will not work at the moment
   //Virus already found
/*
   if (( VirusScannerT->ReadScannerAnswer() != "Clean" ) && ( VirusScannerT->ReadScannerAnswer() != "" ) )
    {

			#ifdef  CATCHONSCANNERERROR
      return -2;
      #else
      if ( VirusScannerT->ReadScannerAnswer() != "Error -2" ){
      return -2;
      }
			#endif
    }
*/

    //Send header only once
    if ( HeaderSend == false )
    {
      ToBrowser.SendHeader(&Header);
      HeaderSend  = true;
    }

    TransferToClient = TransferData.substr(  0 , TransferData.length()- KEEPBACKBUFFER );
    ToBrowser.Send( &TransferToClient );
    TransferData.erase( 0, TransferData.length()- KEEPBACKBUFFER );

   }

   }

//Wait till scanning is complete
TempScannerAnswer =  VirusScannerT->ScanningComplete();
if ( TempScannerAnswer != 0) {
  return TempScannerAnswer;
  }

  
if ( HeaderSend == false )
    {
      ToBrowser.SendHeader(&Header); //Send header only once
    }

  ToBrowser.Send( &TransferData );


return 0;

}


bool ProxyHandler::ProxyMessage( int CommunicationAnswerT , GenericScanner *VirusScannerT)
{

string VirusError=VIRUSFOUND;
string ErrorHeader = ERRORHEADER;
string ScannerError = SCANNERERROR;
string DNSError = DNSERROR;
string Answer;

   if ( HeaderSend == false )
   {
    ToBrowser.Send( &ErrorHeader );
   }

 if ( CommunicationAnswerT == -50 ){
    //Could not resolve DNS Name
    ToBrowser.Send( &ErrorHeader );
    ToBrowser.Send( &DNSError );
    LogFile::AccessMessage("%s %d DNS Failed\n", Host.c_str(), Port);

 } else if ( CommunicationAnswerT == 2 ) {

    Answer = VirusScannerT->ReadScannerAnswer();
    LogFile::AccessMessage("%s %d Scanner Error: %s\n", ToBrowser.Request.c_str(), Port, Answer.c_str());
    ScannerError.insert( ERRORINSERTPOSITION, Answer);
    ToBrowser.Send( &ScannerError );
     
 } else if ( CommunicationAnswerT == 1 ) {
    LogFile::AccessMessage("%s %d Virus: %s\n", ToBrowser.Request.c_str(), Port, Answer.c_str());
    VirusError.insert( VIRUSINSERTPOSITION, Answer);
    ToBrowser.Send( &VirusError );
 }

 
return false;
}


ProxyHandler::ProxyHandler(){
}
ProxyHandler::~ProxyHandler(){
}
