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

bool ProxyHandler::Proxy ( SocketHandler *ProxyServerT, GenericScanner *VirusScannerT )
{
int CommunicationAnswer;

 if ( (CommunicationAnswer = Communication ( ProxyServerT, VirusScannerT )) != 0){
 
   ProxyMessage( CommunicationAnswer );

   ToBrowser.Close();
   ToServer.Close();
   VirusScannerT->ScanningComplete();
   return false;
   }

 LogFile::AccessMessage("%s %d OK\n", ToBrowser.GetCompleteRequest(), ToBrowser.GetPort());
   
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

unsigned long ContentLengthReference = 0;
unsigned long ContentLength = 0;

ssize_t BodyLength = 0;

ssize_t repeat;

HeaderSend = false;

//string TransferData = "";
string TransferToClient = "";

deque <std::string> BodyQueue;
deque <std::string>::iterator TransferData;
string BodyTemp;
int TransferDataLength=0;


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

   if( ToBrowser.AnalyseHeader( &Header, "\n") == false)
   {
     LogFile::ErrorMessage("Could not Analyse header\n%s\n", Header.c_str());
    return -30;
   }

   #if defined (PARENTPROXY) && defined (PARENTPORT)
   if( ToServer.SetDomainAndPort( PARENTPROXY, PARENTPORT ) == false )
   {
     LogFile::ErrorMessage("Could not resolve parent proxy: %s\n", PARENTPROXY);
    return -50;
   }
   #else 
   if( ToServer.SetDomainAndPort( ToBrowser.GetHost(), ToBrowser.GetPort() ) == false )
   {
     LogFile::ErrorMessage("Could not resolve hostname: %s\n", ToBrowser.GetHost() );
    return -50;
   }
   #endif

   
   if( ToServer.ConnectToServer ( ) == false)
   {
     LogFile::ErrorMessage("Could not connect to server %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
    return -60;
   }

   Header = ToBrowser.PrepareHeaderForServer();

   ToServer.SendHeader(&Header);

   ContentLengthReference = ToBrowser.GetContentLength( );

   //Check for Client Body e.g. POST
  if (  ContentLengthReference > 0 ){
     //We expect POST data
     
  repeat =  int (ContentLengthReference / MAXRECV);

  for(int i=0; i <= repeat; i++){
    Body="";
    if ( i == repeat ) {
      int rest = ContentLengthReference - ( MAXRECV * repeat);
      if ( ToBrowser.RecvLength( &Body, rest ) == false ) {
       LogFile::ErrorMessage("Could not read Browser Post: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
       return -70;
      }

    } else {
      if (  ToBrowser.RecvLength( &Body, MAXRECV ) == false ){
       LogFile::ErrorMessage("Could not read Browser Post: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
       return -70;
      }
    }

     ToServer.Send( &Body );

   }

     //IE Bug 
     if ( ToBrowser.CheckForData() == true )
     {
     ToBrowser.Recv( &TempString, false);
     if ( TempString == "\r\n" )
       {
        ToBrowser.RecvLength( &TempString, 2);
       } else {
       LogFile::ErrorMessage("Browser Post was too long: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
       return -75;
        }
     }
    
    }

   if ( ToServer.ReadHeader(&Header) == false){
     LogFile::ErrorMessage("Could not read Server Header: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
     return -80;
    }

   ToServer.AnalyseHeader( &Header, "\n");

   ContentLengthReference = ToServer.GetContentLength( );

   if ( ContentLengthReference > 0 )
   {
      unlock = true;
      //Set tempfile to right size
      if ( VirusScannerT->SetFileSize( ContentLengthReference ) == false )
      {
      LogFile::ErrorMessage("Could set file size: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
      return -90;
      }
   }
         
   Header = ToServer.PrepareHeaderForBrowser();
   


   //Server Body Transfer
   while ( (BodyLength = ToServer.ReadBodyPart(&BodyTemp)) != 0)
   {

   TransferDataLength += BodyLength;

   if( BodyLength == -1) {
     LogFile::ErrorMessage("Could not read Server Body: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
     return -100;
     }


     //Does Browser drop connection
     if(ToBrowser.IsConnectionDropped() == true )
     {
     LogFile::ErrorMessage("Browser dropped Connection: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
     return -110;
     }
     
     //Body size check
     ContentLength += BodyLength;
     if ( (unlock == true) && ( ContentLength > ContentLengthReference ) )
     {
     LogFile::ErrorMessage("ContentLength and Body size does not fit: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
     return -120;
     }
     
     //Add string to queue
     BodyQueue.push_back( BodyTemp );

     //Expand file to scan
     if ( VirusScannerT->ExpandFile( (char *)BodyTemp.c_str(), BodyTemp.length() , unlock ) == false ){
       LogFile::ErrorMessage("Could not expand tempfile: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
      return -130;
      }

    TransferData = BodyQueue.begin();

    if ( KEEPBACKBUFFER < (TransferDataLength - TransferData->length()) ){
  
   //This check will not work at the moment
   //Virus already found?
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

    BodyTemp = *TransferData;
    TransferDataLength -= BodyTemp.length();
    ToBrowser.Send( &BodyTemp );
    BodyQueue.erase( TransferData );
   }

   }

//Wait till scanning is complete
TempScannerAnswer =  VirusScannerT->ScanningComplete();
if ( TempScannerAnswer != 0) {
  #ifdef CATCHONSCANNERERROR
  return TempScannerAnswer;
  #else
  if ( TempScannerAnswer != 2 )
  {
   return TempScannerAnswer; 
  }
  #endif
}

  
if ( HeaderSend == false )
    {
      ToBrowser.SendHeader(&Header); //Send header only once
    }


for(TransferData = BodyQueue.begin(); TransferData != BodyQueue.end(); ++TransferData)
 {
  BodyTemp = *TransferData;
  ToBrowser.Send( &BodyTemp );
 }


return 0;

}


bool ProxyHandler::ProxyMessage( int CommunicationAnswerT )
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
    ToBrowser.Send( &DNSError );
    LogFile::AccessMessage("%s %d DNS Failed\n", ToBrowser.GetHost(), ToBrowser.GetPort());

 } else if ( CommunicationAnswerT == 2 ) {
    LogFile::AccessMessage("%s %d Scanner Error: %s\n", ToBrowser.GetHost(), ToBrowser.GetPort(), Answer.c_str());
    ScannerError.insert( ERRORINSERTPOSITION, Answer);
    ToBrowser.Send( &ScannerError );
     
 } else if ( CommunicationAnswerT == 1 ) {
    LogFile::AccessMessage("%s Virus: %s\n", ToBrowser.GetCompleteRequest(), Answer.c_str());
    VirusError.insert( VIRUSINSERTPOSITION, Answer);
    ToBrowser.Send( &VirusError );
 } else {
      LogFile::AccessMessage("%s Error: %d\n", ToBrowser.GetCompleteRequest(), CommunicationAnswerT);
 }

 
return false;
}


ProxyHandler::ProxyHandler(){
}
ProxyHandler::~ProxyHandler(){
}
