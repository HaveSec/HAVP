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
#include "whitelist.h"

extern URLList Whitelist;
extern URLList Blacklist;

bool ProxyHandler::Proxy ( SocketHandler *ProxyServerT, GenericScanner *VirusScannerT )
{
    int CommunicationAnswer;

    if ( (CommunicationAnswer = Communication ( ProxyServerT, VirusScannerT )) != 0)
    {

        //ScannningComplete was not called
        if (( CommunicationAnswer > -200 ) && ( CommunicationAnswer < 0 )) {
        VirusScannerT->ScanningComplete();
        }

   	ProxyMessage( CommunicationAnswer , VirusScannerT);

        ToBrowser.Close();
        ToServer.Close();

        return false;
    }


// #ifdef LOG_OKS
    if(Params::GetConfigBool("LOG_OKS"))
    LogFile::AccessMessage("%s %s %d %d %s OK\n", ToBrowser.GetIP().c_str(), ToBrowser.GetCompleteRequest(), ToServer.GetResponse(), ToBrowser.GetPort(), ToBrowser.GetRequestType().c_str() );
// #endif

//PSE: withdraw Clean-message
    string ans = VirusScannerT->ReadScannerAnswer();

    ToBrowser.Close();
    ToServer.Close();

    return true;
}




int ProxyHandler::Communication( SocketHandler *ProxyServerT, GenericScanner *VirusScannerT)
{

    bool ScannerOff;
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
    BrowserDropped = false;

    //string TransferData = "";
    string TransferToClient = "";

    deque <std::string> BodyQueue;
    deque <std::string>::iterator TransferData;
    string BodyTemp;
    int TransferDataLength=0;

    unsigned int maxscansize = Params::GetConfigInt("MAXSCANSIZE");
    int TricklingTime = Params::GetConfigInt("TRICKLING");
    unsigned int KeepBackBuffer = Params::GetConfigInt("KEEPBACKBUFFER");

    //Clear old session variables
    ToBrowser.ClearVars();

    if( ProxyServerT->AcceptClient( &ToBrowser ) == false)
    {
        BrowserDropped = true;
        LogFile::ErrorMessage("Could not accept browser\n");
        return -10;
    }


    if( ToBrowser.ReadHeader( &Header ) == false)
    {
        BrowserDropped = true;
        LogFile::ErrorMessage("Could not read header from browser\n");
        return -20;
    }

    if( ToBrowser.AnalyseHeader( &Header, "\n") == false)
    {
        LogFile::ErrorMessage("Could not Analyse header\n%s\n", Header.c_str());
        return -30;
    }

    if( (ToBrowser.GetRequestType() == "") || (ToBrowser.GetHost() == NULL) )
    {
        LogFile::ErrorMessage("Malformed request received\n");
        return -35;
    }

#ifdef REWRITE
    ToBrowser.RewriteHost();
#endif

    ScannerOff = Whitelist.URLFound ( ToBrowser.GetHost(), ToBrowser.GetRequest() );

    if ( Blacklist.URLFound ( ToBrowser.GetHost(), ToBrowser.GetRequest() ) == true ) {
      LogFile::ErrorMessage("URL is blacklisted: %s\n", ToBrowser.GetCompleteRequest() );
      return -45;
    }

    // #if defined (PARENTPROXY) && defined (PARENTPORT)
    string parentproxy=Params::GetConfigString("PARENTPROXY");
    int parentport=Params::GetConfigInt("PARENTPORT");
    if( parentproxy != "" && parentport != 0 ) {
    if( ToServer.SetDomainAndPort( parentproxy.c_str(), parentport ) == false )
    {
        LogFile::ErrorMessage("Could not resolve parent proxy: %s\n", parentproxy.c_str() );
        return -50;
    }
    // #else
    } else {
    if( ToServer.SetDomainAndPort( ToBrowser.GetHost(), ToBrowser.GetPort() ) == false )
    {
        LogFile::ErrorMessage("Could not resolve hostname: %s\n", ToBrowser.GetHost() );
        return -50;
    }
    // #endif
    }

    if( ToServer.ConnectToServer ( ) == false)
    {
        LogFile::ErrorMessage("Could not connect to server %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
        return -60;
    }

    Header = ToBrowser.PrepareHeaderForServer();

    if (ToServer.SendHeader(&Header) == false)
    {
        LogFile::ErrorMessage("Could not send Header to server server %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
        return -67;
    }

    ContentLengthReference = ToBrowser.GetContentLength( );

    //Check for Client Body e.g. POST
    if (  ContentLengthReference > 0 )
    {
        //We expect POST data

        repeat =  int (ContentLengthReference / MAXRECV);

        for(int i=0; i <= repeat; i++)
        {
            Body="";
            if ( i == repeat )
            {
                int rest = ContentLengthReference - ( MAXRECV * repeat);
                if ( ToBrowser.RecvLength( &Body, rest ) == false )
                {
                    BrowserDropped = true;
                    LogFile::ErrorMessage("Could not read Browser Post: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
                    return -70;
                }

            }
            else
            {
                if (  ToBrowser.RecvLength( &Body, MAXRECV ) == false )
                {
                    BrowserDropped = true;
                    LogFile::ErrorMessage("Could not read Browser Post: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
                    return -70;
                }
            }

            if (ToServer.Send( &Body ) == false)
            {
              LogFile::ErrorMessage("Could not send Body to server server %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
              return -75;
            }


        }

        //IE Bug
        if ( ToBrowser.CheckForData() == true )
        {
            if ( ToBrowser.Recv( &TempString, false) < 0)
            {
              BrowserDropped = true;
              LogFile::ErrorMessage("Could not check for IE POST Bug %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
              return -76;
            } else if ( TempString == "\r\n" )
            {
                ToBrowser.RecvLength( &TempString, 2);
            } else if (TempString == "" )
            {
              //Browser shut down send. This could be ok??
            }
            else
            {
                BrowserDropped = true;
                LogFile::ErrorMessage("Browser Post was too long: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
                return -79;
            }
        }

    }

    if ( ToServer.ReadHeader(&Header) == false)
    {
        LogFile::ErrorMessage("Could not read Server Header: %s Port %d\n", ToBrowser.GetCompleteRequest(), ToBrowser.GetPort());
        return -80;
    }

    if( ToServer.AnalyseHeader( &Header, "\n") == false)
    {
        LogFile::ErrorMessage("Could not Analyse Server Header: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
        return -85;
    }


    ContentLengthReference = ToServer.GetContentLength( );

    //Also check if file is too large for scanning
    if ( (ScannerOff != true) && ( ContentLengthReference > 0 ) && ( ( ContentLengthReference < maxscansize ) || (maxscansize == 0) ) )
    {
        unlock = true;
        //Set tempfile to right size
        if ( VirusScannerT->SetFileSize( ContentLengthReference ) == false )
        {
            LogFile::ErrorMessage("Could set file size - Check disk space: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
            return -90;
        }
    }

    Header = ToServer.PrepareHeaderForBrowser();


 //Not Modified no Body expected or HEAD with no body
 if( (ToServer.GetResponse() != 304 ) && (ToServer.GetResponse() != -302 ) && (ToBrowser.GetRequestType() != "HEAD") ) {

    //Start Time for Trickling
    time_t LastTrickling = time(NULL);

    //Server Body Transfer
    while ( (BodyLength = ToServer.ReadBodyPart(&BodyTemp)) != 0)
    {

        TransferDataLength += BodyLength;

        if( BodyLength == -1)
        {
            LogFile::ErrorMessage("Could not read Server Body: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
            return -100;
        }

        //Does Browser drop connection
        if(ToBrowser.IsConnectionDropped() == true )
        {
            BrowserDropped = true;
            LogFile::ErrorMessage("Browser dropped Connection: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
            return -110;
        }

        //Body size check
        ContentLength += BodyLength;
        if ( (unlock == true) && (ScannerOff != true) && ( ContentLength > ContentLengthReference ) )
        {
            LogFile::ErrorMessage("ContentLength and Body size does not fit - body too long: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
            return -120;
        }


        //Add string to queue
        BodyQueue.push_back( BodyTemp );

        //File to large for scanning
        if ( (maxscansize != 0) && ( ContentLength > maxscansize ) )
        {
         ScannerOff = true;
        }

        if (ScannerOff != true) 
        {
          //Expand file to scan
          if ( VirusScannerT->ExpandFile( (char *)BodyTemp.c_str(), BodyTemp.length() , unlock ) == false )
          {
            LogFile::ErrorMessage("Could not expand tempfile - Check disk space: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
            return -130;
          }
        }

        TransferData = BodyQueue.begin();

        //Trickling
        if ((TricklingTime != 0) && (LastTrickling + TricklingTime < time(NULL)))
        {
            //Send header only once
            if ( HeaderSend == false )
            {
                HeaderSend  = true;
                if( ToBrowser.SendHeader(&Header) == false)
                {
                  BrowserDropped = true;
                  LogFile::ErrorMessage("Could not send Header to Browser: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
                  return -135;
                }
            }
         LastTrickling = time(NULL);

         BodyTemp = *TransferData;
         TransferDataLength -= 1; //send one character
         string character = TransferData->substr(0,1);
         TransferData->erase(0,1);
         if (ToBrowser.Send( &character ) == false)
            {
              BrowserDropped = true;
              LogFile::ErrorMessage("Could not send Body to Browser: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
              return -138;
            }

         if ( TransferData->size() == 0 )
         {
            BodyQueue.erase( TransferData );
         }
        }


        //Send Data
        if ( KeepBackBuffer < (TransferDataLength - TransferData->length()) )
        {

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
                HeaderSend  = true;
                if( ToBrowser.SendHeader(&Header) == false)
                {
                  BrowserDropped = true;
                  LogFile::ErrorMessage("Could not send Header to Browser: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
                  return -135;
                }
            }

            BodyTemp = *TransferData;
            TransferDataLength -= BodyTemp.length();
            if (ToBrowser.Send( &BodyTemp ) == false)
            {
              BrowserDropped = true;
              LogFile::ErrorMessage("Could not send Body to Browser: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
              return -138;
            }
            BodyQueue.erase( TransferData );
        }

      //End while because file is complete.
      if ( ContentLength == ContentLengthReference ){
        break;
      }

    }//while
 } 

// Check if there is some body e.g head
//    if ( (ToBrowser.GetRequestType() != "HEAD") && (ContentLengthReference != 0) && (ScannerOff != true) && ( ContentLength != ContentLengthReference )){ 
//            LogFile::ErrorMessage("ContentLength and Body size does not fit - body too short: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());;
//      return -121;
//    }


    //Wait till scanning is complete
    TempScannerAnswer =  VirusScannerT->ScanningComplete();

    //Should we listen on the scanner output?
    if (ScannerOff == true) {
        TempScannerAnswer = 0;
    }

    if ( TempScannerAnswer != 0)
    {
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
        HeaderSend = true;
        if ( ToBrowser.SendHeader(&Header) == false)
        {
          BrowserDropped = true;
          LogFile::ErrorMessage("Could not send Header to Browser: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
          return -201;
        }
 
    }

    for(TransferData = BodyQueue.begin(); TransferData != BodyQueue.end(); ++TransferData)
    {
        BodyTemp = *TransferData;
        if( ToBrowser.Send( &BodyTemp ) == false)
        {
          BrowserDropped = true;
          LogFile::ErrorMessage("Could not send Body to Browser: %s Port %d\n", ToBrowser.GetHost(), ToBrowser.GetPort());
          return -202;
        }

    }

    return 0;

}


//PSE: new function call
//bool ProxyHandler::ProxyMessage( int CommunicationAnswerT )
bool ProxyHandler::ProxyMessage( int CommunicationAnswerT , GenericScanner *VirusScannerT)
{

    string Answer;

    long size;
    char* buffer;
    char ErrorNumber[11];
    FileHandler fileH;
    string filename;
    string sendout="";
    string message="";
    string searchstring = "<!--message-->";


    //PSEstart
    //PSE: now get the answer from the second process
     Answer = VirusScannerT->ReadScannerAnswer();
    //PSEend

    if (BrowserDropped ==true ){
     LogFile::AccessMessage("%s %s Browser Droped: %d\n", ToBrowser.GetIP().c_str(), ToBrowser.GetCompleteRequest(), CommunicationAnswerT);
     return false;
    }

    if ( HeaderSend == false )
    {
       string errorheader = ERRORHEADER;
       if (ToBrowser.Send( &errorheader ) == false) {
         LogFile::AccessMessage("%s %s Browser Droped: %d\n", ToBrowser.GetIP().c_str(), ToBrowser.GetCompleteRequest(), CommunicationAnswerT);
         return false;
       }
    }

    if ( CommunicationAnswerT == -120 )
    {
        //More Data than Content-Length
        LogFile::AccessMessage("$s %s %d Data larger than Content-Length\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost(), ToBrowser.GetPort());
        message = "Server sends more data than expected<br>";
        message =+ ToBrowser.GetHost();
        filename = ERROR_INVALID;
    }
    else if ( CommunicationAnswerT == -85 )
    {
        LogFile::AccessMessage("%s %s %d Invalid Server Header\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost(), ToBrowser.GetPort());
        message = "Invalid Server Header<br>";
        message =+ ToBrowser.GetHost();
        filename = ERROR_INVALID;
    }
    else if ( ( CommunicationAnswerT == -60 ) || ( CommunicationAnswerT == -67 ) || ( CommunicationAnswerT == -75 ) || ( CommunicationAnswerT == -80 ) )
    {
        LogFile::AccessMessage("%s %s %d Server down\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost(), ToBrowser.GetPort());
        message = ToBrowser.GetHost();
        filename = ERROR_DOWN;
    }
    else if ( CommunicationAnswerT == -50 )
    {
        //Could not resolve DNS Name
        LogFile::AccessMessage("%s %s %d DNS Failed\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost(), ToBrowser.GetPort());
        message = ToBrowser.GetHost();
        filename = ERROR_DNS;
    }
    else if ( CommunicationAnswerT == -45 )
    {
        LogFile::AccessMessage("$s URL %s is blacklisted\n", ToBrowser.GetIP().c_str(), ToBrowser.GetCompleteRequest() );
        message = ToBrowser.GetCompleteRequest();
        filename = ERROR_BLACKLIST;
    }
    else if ( CommunicationAnswerT == -35 )
    {
        //LogFile::AccessMessage("URL %s is blacklisted\n", ToBrowser.GetCompleteRequest() );
        message = "Only HTTP is supported";
        filename = ERROR_REQUEST;
    }
    else if ( CommunicationAnswerT == 2 )
    {
        LogFile::AccessMessage("%s %s %d Scanner Error: %s\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost(), ToBrowser.GetPort(), Answer.c_str());
        message = Answer;
        filename = ERROR_SCANNER;
    }
    else if ( CommunicationAnswerT == 1 )
    {
        LogFile::AccessMessage("%s %s Virus: %s\n", ToBrowser.GetIP().c_str(), ToBrowser.GetCompleteRequest(), Answer.c_str());
        message = Answer;
        filename = VIRUS_FOUND;
    }
    else
    {
        LogFile::AccessMessage("%s %s Error: %d - Status %d - Method %s\n", ToBrowser.GetIP().c_str(), ToBrowser.GetCompleteRequest(), CommunicationAnswerT, ToServer.GetResponse(), ToBrowser.GetRequestType().c_str() );
        snprintf(ErrorNumber, 10, "%d", CommunicationAnswerT);
        message = ErrorNumber;
        filename = ERROR_BODY;
    }


    //Danny
    if (filename.size() > 0) {
      	string path=Params::GetConfigString("TEMPLATEPATH");
      	filename = path + "/" + filename;
        size = fileH.FileSize(filename.c_str());
	if(size) {  // size=0 if error on open
        buffer = new char[size+1];
        fileH.FileRead(filename.c_str(), buffer, size);
        buffer[size] = '\0';
        sendout = buffer;

        if (message.size() > 0) {
            fileH.SearchReplace(sendout, searchstring, message);
        } 
        ToBrowser.Send( &sendout );
        delete buffer;
	}
    }
    
    return false;
}


ProxyHandler::ProxyHandler()
{
newinstance = true;
}


ProxyHandler::~ProxyHandler()
{
}
