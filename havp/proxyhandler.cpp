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
    return -1;
   }

   if( ToBrowser.ReadHeader( &Header ) == false)
   {
     LogFile::ErrorMessage("Could not read header from browser\n");
    return -2;
   }

   if( ToBrowser.TokenizeHeader( &Header, "\r\n") == false)
   {
     LogFile::ErrorMessage("Could not torkenize header\n%s\n", Header.c_str());
    return -3;
   }


   if( ToBrowser.GetHostAndPort( &Host, &Port ) == false)
   {
     LogFile::ErrorMessage("Could not get host of header\n%s\n", Header.c_str());
     return -4;
   }

   if( ToServer.SetDomainAndPort( (char*)Host.c_str(), Port ) == false )
   {
     LogFile::ErrorMessage("Could not resolve hostname: %s\n", Host.c_str());
    return -5;
   }

   if( ToServer.ConnectToServer ( ) == false)
   {
     LogFile::ErrorMessage("Could not connect to server %s Port %d\n", Host.c_str(), Port);
    return -6;
   }

   Header = ToBrowser.PrepareHeaderForServer();

   ToServer.SendHeader(&Header);

   ContentLengthReference = ToBrowser.GetContentLength( &Header );


  if (  ContentLengthReference != 0 ){
     //We expect POST data
     Body="";
     if ( ToBrowser.RecvLength( &Body, ContentLengthReference) == false )
     {
     LogFile::ErrorMessage("Could not read Browser Post: %s Port %d\n", ToBrowser.Request.c_str(), Port);
     return -17;
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
     return -7;
    }

   ToServer.TokenizeHeader( &Header, "\r\n");

   ContentLengthReference = ToServer.GetContentLength( &Header );

   if ( ContentLengthReference > 0 )
   {
      unlock = true;
      //Set tempfile to right size
      if ( VirusScannerT->SetFileSize( ContentLengthReference ) == false )
      {
      LogFile::ErrorMessage("Could set file size: %s Port %d\n", ToBrowser.Request.c_str(), Port);
      return -14;
      }
   }
         
   Header = ToServer.PrepareHeaderForBrowser();
   
   //Transfer Body
   while ( (BodyLength = ToServer.ReadBodyPart(&Body)) != 0)
   {

   if( BodyLength == -1) {
     LogFile::ErrorMessage("Could not read Server Body: %s Port %d\n", ToBrowser.Request.c_str(), Port);
     return -8;
     }

     //Body size check
     ContentLength += BodyLength;
     if ( (unlock == true) && ( ContentLength > ContentLengthReference ) )
     {
     LogFile::ErrorMessage("ContentLength and Body size does not fit: %s Port %d\n", ToBrowser.Request.c_str(), Port);
     return -9;
     }
     
     //String add
     TransferData += Body;

     //Expand file to scan
     if ( VirusScannerT->ExpandFile( (char *)Body.c_str(), Body.length() , unlock ) == false ){
       LogFile::ErrorMessage("Could not expand tempfile: %s Port %d\n", ToBrowser.Request.c_str(), Port);
      return -20;
      }

   if ( TransferData.length() > KEEPBACKBUFFER ){
  
   //Virus already found
   if (( VirusScannerT->ReadScannerAnswer() != "Clean" ) && ( VirusScannerT->ReadScannerAnswer() != "" ) )
    {

			#ifdef  CATCHONSCANNERERROR
      return -100;
      #else
      if ( VirusScannerT->ReadScannerAnswer() != "Error -2" ){
      return -100
      }
			#endif
   
    }

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
if ( VirusScannerT->ScanningComplete() == false) {
  return -101;
  }

if ( HeaderSend == false )
    {
      ToBrowser.SendHeader(&Header); //Header senden nur einmal
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
string Error;

//Ist scanner already terminated
if ( CommunicationAnswerT != -101 ){
   VirusScannerT->ScanningComplete();
   }

 if ( CommunicationAnswerT == -5 ){
    //Could not resolve DNS Name
    ToBrowser.Send( &ErrorHeader );
    ToBrowser.Send( &DNSError );
    LogFile::AccessMessage("%s %d ", Host.c_str(), Port);
    LogFile::AccessMessage("DNS Failed\n");

  } else if ( CommunicationAnswerT == -7 ) {
     LogFile::AccessMessage("%s %d No Server Header\n", ToBrowser.Request.c_str(), Port);

  } else if ( CommunicationAnswerT == -8 ) {
     LogFile::AccessMessage("%s %d No Server Body\n", ToBrowser.Request.c_str(), Port);


 } else if (( CommunicationAnswerT == -100 ) || ( CommunicationAnswerT == -101 )) {

   if ( HeaderSend == false )
   {
    ToBrowser.Send( &ErrorHeader );
   }

    Answer = VirusScannerT->ReadScannerAnswer();

    if ( Answer == "Error -2"){

     Error = VirusScannerT->ReadErrorAnswer();
     LogFile::AccessMessage("%s %d Scanner Error: %s\n", ToBrowser.Request.c_str(), Port, Error.c_str());
     ScannerError.insert( ERRORINSERTPOSITION, Error);
     ToBrowser.Send( &ScannerError );
    } else {
    LogFile::AccessMessage("%s %d Virus: %s\n", ToBrowser.Request.c_str(), Port, Answer.c_str());
    VirusError.insert( VIRUSINSERTPOSITION, Answer);
    ToBrowser.Send( &VirusError );
    }


 } else {
    LogFile::AccessMessage("%s %d - Unknown Error\n", ToBrowser.Request.c_str(), Port);
    LogFile::ErrorMessage("%s %d - Unknown Error\n", ToBrowser.Request.c_str(), Port);
 } 
return false;
}


ProxyHandler::ProxyHandler(){
}
ProxyHandler::~ProxyHandler(){
}
