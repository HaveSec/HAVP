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

#include "default.h"
#include "proxyhandler.h"
#include "whitelist.h"
#include "utils.h"

extern URLList Whitelist;
extern URLList Blacklist;
extern int LL; //LogLevel

bool ProxyHandler::Proxy( SocketHandler *ProxyServerT, GenericScanner *VirusScannerT )
{
    extern bool childrestart;

    //By default scanner will continue
    char Scannercmd[] = "c\0";

    string Header, Answer;
    int ret, CommunicationAnswer;

    bool Looping = true;
    bool ScannerOff = false;

    int requests = 0;
    alivecount = 0;

    ServerConnected = BrowserDropped = DropBrowser = false;

    //Wait for first connection
    while ( ProxyServerT->AcceptClient( &ToBrowser ) == false ) sleep(10);

    do { //PROCESSING LOOP

        ++requests;

        if ( DropBrowser || BrowserDropped )
        {
            //Close browser connection
            ToBrowser.Close();

            //Close server connection if open
            if ( ServerConnected )
            {
                ToServer.Close();
                ServerConnected = false;
            }

            //Reset keepalive count
            alivecount = 0;

            //Wait for new connection
            while ( ProxyServerT->AcceptClient( &ToBrowser ) == false ) sleep(10);
        }

        //Clear request variables
        ToBrowser.ClearVars();
        ToServer.ClearVars();
        ScannerUsed = UnlockDone = AnswerDone = ReinitDone = HeaderSend = BrowserDropped = DropBrowser = DropServer = ServerClosed = false;

        if ( ++alivecount > 1 )
        {
            //Keep-Alive timeout 10 seconds
            if ( ToBrowser.CheckForData(10) == false )
            {
                DropBrowser = true;
                continue;
            }
        }

        if ( ToBrowser.ReadHeader( &Header ) == false )
        {
            if (LL>0) if (alivecount==1) LogFile::ErrorMessage("(%s) Could not read browser header\n", ToBrowser.GetIP().c_str());
            DropBrowser = true;
            continue;
        }

        if ( (ret = ToBrowser.AnalyseHeader( &Header )) < 0 )
        {
            if (LL>0) LogFile::ErrorMessage("(%s) Invalid request from browser\n", ToBrowser.GetIP().c_str());
            ProxyMessage( ret, "" );
            DropBrowser = true;
            continue;
        }

        if ( ToBrowser.GetHost() == "" || ToBrowser.GetPort() == -1 )
        {
            LogFile::ErrorMessage("(%s) Invalid request from browser (no Host-header?)\n", ToBrowser.GetIP().c_str());
            ProxyMessage( -201, "" );
            DropBrowser = true;
            continue;
        }

#ifdef REWRITE
        ToBrowser.RewriteHost();
#endif

#ifdef SSLTUNNEL
    //Whitelist/blacklist can not be checked on SSL requests
    if ( ToBrowser.GetRequestProtocol() != "connect" ) {
#endif

        //Whitelisted?
        ScannerOff = Whitelist.URLFound( ToBrowser.GetHost(), ToBrowser.GetRequest() );

        if ( (ScannerOff == false) || (Params::GetConfigBool("WHITELISTFIRST") == false) )
        {
            if ( Blacklist.URLFound( ToBrowser.GetHost(), ToBrowser.GetRequest() ) )
            {
		ToBrowser.PrepareHeaderForServer();
                ProxyMessage( -45, "" );
                DropBrowser = true;
                continue;
            }
        }

#ifdef SSLTUNNEL
    }
#endif

        //Keep-Alive?
        if ( ToBrowser.KeepItAlive() == false || ToBrowser.GetRequestType() != "GET" || (alivecount == 100) )
        {
            DropBrowser = true;
        }

        //HTTP REQUEST
        if ( ToBrowser.GetRequestProtocol() == "http" )
        {
            CommunicationAnswer = CommunicationHTTP( VirusScannerT, ScannerOff );
        }
        //FTP REQUEST
        else if ( ToBrowser.GetRequestProtocol() == "ftp" )
        {
            if ( (Params::GetConfigString("PARENTPROXY") != "") && (Params::GetConfigInt("PARENTPORT") > 0) )
            {
                CommunicationAnswer = CommunicationHTTP( VirusScannerT, ScannerOff );
            }
            else
            {
                //TODO: Support ftp even without parentproxy :-)
                ProxyMessage( -110, "" );
                DropBrowser = true;
                continue;
            }
        }
#ifdef SSLTUNNEL
        //SSL CONNECT REQUEST
        else if ( ToBrowser.GetRequestProtocol() == "connect" )
        {
            //Drop Keep-Alive
            if ( ServerConnected ) ToServer.Close();

            CommunicationAnswer = CommunicationSSL();

            //Close connection
            ToServer.Close();
            ServerConnected = false;

            if ( CommunicationAnswer != 0 ) ProxyMessage( CommunicationAnswer, "" );

            DropBrowser = true;
            continue;
        }
#endif

        //Retry GET connection once if ReadHeader error (-80) or Connect error (-60, -61)
        //Also reconnect if server closed Keep-Alive connection (-60)
        if ( (CommunicationAnswer == -80 && ToBrowser.GetRequestType() == "GET") || CommunicationAnswer == -60 || CommunicationAnswer == -61 )
        {
            ToServer.Close();
            ServerConnected = false;

            //Sleep second before retry
            sleep(1);

            CommunicationAnswer = CommunicationHTTP( VirusScannerT, ScannerOff );

            //No need to stop Keep-Alive if retry is clean
            if ( CommunicationAnswer == 0 ) DropServer = false;
        }

        //Make sure server connection is closed if needed
        if ( ServerClosed == false && (DropServer || DropBrowser || BrowserDropped) )
        {
            ToServer.Close();
            ServerConnected = false;
        }

        //Check scanner
        if ( ScannerUsed )
        {
            if ( UnlockDone == false ) VirusScannerT->UnlockFile();
            if ( AnswerDone == false ) VirusScannerT->CheckScanner(true);
            if ( ReinitDone == false ) VirusScannerT->ReinitFile();

            Answer = VirusScannerT->ReadScannerAnswer();
        }

        if ( CommunicationAnswer != 0 )
        {
            //Request not clean
            ProxyMessage( CommunicationAnswer, Answer );
            DropBrowser = true;
        }
        else if ( Params::GetConfigBool("LOG_OKS") )
        {
            //Clean request
            LogFile::AccessMessage("%s %s %d %s OK\n", ToBrowser.GetIP().c_str(), ToBrowser.GetCompleteRequest().c_str(), ToServer.GetResponse(), ToBrowser.GetRequestType().c_str() );
        }

        //Signal scanner
        if ( ScannerUsed )
        {
            //Exit processes if restart signaled or maximum reqs reached
            if ( (DropBrowser || BrowserDropped) && (childrestart || (requests > 1000)) )
            {
                Scannercmd[0] = 'q';
                Looping = false;
            }

            while ((ret = write(VirusScannerT->commout[1], Scannercmd, 1)) < 0)
            {
                if (errno == EINTR) continue;
                Looping = false;
                break;
            }
            if (ret == 0) break;
        }

    } while ( Looping ); //END PROCESSING

    //Make sure browser connection is closed
    ToBrowser.Close();

    //End process
    exit(1);
}


int ProxyHandler::CommunicationHTTP( GenericScanner *VirusScannerT, bool ScannerOff )
{

    long long ContentLengthReference = ToBrowser.GetContentLength();

    //Check that POST has Content-Length
    if ( (ToBrowser.GetRequestType() == "POST") && (ContentLengthReference == -1) )
    {
        BrowserDropped = true;
        LogFile::ErrorMessage("(%s) Browser POST without Content-Length header\n", ToBrowser.GetIP().c_str());
        return -10;
    }

    string parentproxy = Params::GetConfigString("PARENTPROXY");
    int parentport = Params::GetConfigInt("PARENTPORT");

    //Make server connection
    if ( parentproxy != "" && parentport > 0 )
    {
        if ( ServerConnected == false )
        {
            if ( ToServer.SetDomainAndPort( parentproxy, parentport ) == false )
            {
                LogFile::ErrorMessage("Could not resolve parent proxy (%s)\n", parentproxy.c_str() );
                return -51;
            }
            if ( ToServer.ConnectToServer() == false )
            {
                LogFile::ErrorMessage("Could not connect to parent proxy (%s:%d)\n", parentproxy.c_str(), parentport);
                return -61;
            }
        }
    }
    else
    {
        //We need to close Keep-Alive connection if host to connect changes
        if ( ServerConnected && (ToBrowser.GetHost() != ConnectedHost || ToBrowser.GetPort() != ConnectedPort) )
        {
            ToServer.Close();
            ServerConnected = false;
        }

        if ( ServerConnected == false )
        {
            if ( ToServer.SetDomainAndPort( ToBrowser.GetHost(), ToBrowser.GetPort() ) == false )
            {
                if (LL>0) LogFile::ErrorMessage("Could not resolve hostname (%s)\n", ToBrowser.GetHost().c_str() );
                return -50;
            }
            if ( ToServer.ConnectToServer() == false )
            {
                if (LL>0) LogFile::ErrorMessage("Could not connect to server (%s:%d)\n", ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
                return -60;
            }

            ConnectedHost = ToBrowser.GetHost();
            ConnectedPort = ToBrowser.GetPort();
        }
    }

    //We are now connected
    ServerConnected = true;

    string Header = ToBrowser.PrepareHeaderForServer();

    //Send header to server
    if ( ToServer.SendHeader( Header, DropBrowser ) == false )
    {
        if (LL>0) LogFile::ErrorMessage("(%s) Could not send header to server (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
        DropServer = true;
        return -60;
    }

    //Check for client body
    if ( ContentLengthReference >= 0 )
    {
        //Transfer body if there is some
        if ( ContentLengthReference > 0 )
        {
            int repeat = int (ContentLengthReference / MAXRECV);
            string Body;

            for(int i=0; i <= repeat; i++)
            {
                Body = "";

                if ( i == repeat )
                {
                    int rest = ContentLengthReference - (MAXRECV * repeat);

                    if ( ToBrowser.RecvLength( &Body, rest ) == false )
                    {
                        BrowserDropped = true;
                        if (LL>0) LogFile::ErrorMessage("(%s) Could not read browser body\n", ToBrowser.GetIP().c_str());
                        return -10;
                    }
                }
                else
                {
                    if ( ToBrowser.RecvLength( &Body, MAXRECV ) == false )
                    {
                        BrowserDropped = true;
                        if (LL>0) LogFile::ErrorMessage("(%s) Could not read browser body\n", ToBrowser.GetIP().c_str());
                        return -10;
                    }
                }

                if ( ToServer.Send( &Body ) == false )
                {
                    if (LL>0) LogFile::ErrorMessage("(%s) Could not send browser body to server (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
                    DropServer = true;
                    return -75;
                }
            }
        }

        //Check for extra CRLF (IE Bug or Content-Length: 0)
        if ( ToBrowser.CheckForData(0) )
        {
            string TempString;

            if ( ToBrowser.Recv( &TempString, true ) < 0 )
            {
                BrowserDropped = true;
                if (LL>0) LogFile::ErrorMessage("(%s) Could not finish browser body transfer\n", ToBrowser.GetIP().c_str());
                return -10;
            }

            //It is OK if browser finished (empty) or extra CRLF received
            if ( TempString.find_first_not_of( "\r\n", 0 ) != string::npos )
            {
                BrowserDropped = true;
                if (LL>0) LogFile::ErrorMessage("(%s) Browser body was too long\n", ToBrowser.GetIP().c_str());
                return -10;
            }
        }

    }

    //Get response from server
    if ( ToServer.ReadHeader( &Header ) == false )
    {
        if (LL>0) LogFile::ErrorMessage("(%s) Could not read server header (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
        DropServer = true;
        return -80;
    }

    int ret = ToServer.AnalyseHeader( &Header );

    if ( ret < 0 )
    {
        if (LL>0) LogFile::ErrorMessage("(%s) Invalid server header received (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
        DropServer = true;
        return ret;
    }

    //Server did not send Keep-Alive header, close after request (we can keep browser open)
    if ( ToServer.KeepItAlive() == false ) DropServer = true;

    ContentLengthReference = ToServer.GetContentLength();

    if ( ContentLengthReference == -1 )
    {
        //No Keep-Alive for unknown length
        DropBrowser = true;
    }
    else if ( (ContentLengthReference > 0) && (ContentLengthReference < 10) )
    {
        //Forget scanning for tiny files
        ScannerOff = true;
    }

    Header = ToServer.PrepareHeaderForBrowser();

    //No body expected? Not much to be done then
    if ( (ToServer.GetResponse() == 304) || (ContentLengthReference == 0) || (ToBrowser.GetRequestType() == "HEAD") || (ToServer.GetResponse() == 204) )
    {
        //Send header to browser
        if ( ToBrowser.SendHeader( Header, DropBrowser ) == false )
        {
            BrowserDropped = true;
            if (LL>0) LogFile::ErrorMessage("(%s) Could not send header to browser\n", ToBrowser.GetIP().c_str());
            return -10;
        }

        //Check for extra CRLF
        if ( ToServer.CheckForData(0) )
        {
            string BodyTemp;
            ssize_t BodyLength = ToServer.Recv( &BodyTemp, true );
            if ( (BodyLength > 0) && (BodyTemp.find_first_not_of( "\r\n", 0 ) != string::npos) )
            {
                LogFile::ErrorMessage("(%s) Server tried to send body when not expected (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
                DropServer = true;
            }
        }

        //Return clean
        return 0;
    }

    string BodyTemp;

    //If scanning is not needed, use this quick send loop
    if ( ScannerOff )
    {
        //Read first part of body
        ssize_t BodyLength = ToServer.ReadBodyPart( &BodyTemp );

        //Server disconnected?
        if ( BodyLength < 0 )
        {
            if (LL>0) LogFile::ErrorMessage("(%s) Could not read server body (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            DropServer = true;
            return -75;
        }

        //Nothing received?
        if ( BodyLength == 0 )
        {
            //Lets be safe and close all connections
            DropBrowser = true;

            //Send header to browser
            if ( ToBrowser.SendHeader( Header, DropBrowser ) == false )
            {
                BrowserDropped = true;
                if (LL>0) LogFile::ErrorMessage("(%s) Could not send header to browser\n", ToBrowser.GetIP().c_str());
                return -10;
            }

            //Return clean
            return 0;
        }

        //Send header to browser
        if ( ToBrowser.SendHeader( Header, DropBrowser ) == false )
        {
            BrowserDropped = true;
            if (LL>0) LogFile::ErrorMessage("(%s) Could not send header to browser\n", ToBrowser.GetIP().c_str());
            return -10;
        }

        long long ContentLength = BodyLength;

        //Server Body Transfer Loop
        for(;;)
        {
            //If we received more than Content-Length, discard the rest
            if ( (ContentLengthReference > 0) && (ContentLength > ContentLengthReference) )
            {
                BodyTemp.erase( BodyTemp.size() - (ContentLength - ContentLengthReference) );

                ContentLength = ContentLengthReference;

                if (LL>0) LogFile::ErrorMessage("(%s) Server sent more than Content-Length (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());

                //Drop server connection (we can keep browser open)
                DropServer = true;
            }

            //Send body to browser
            if ( ToBrowser.Send( &BodyTemp ) == false )
            {
                BrowserDropped = true;
                if (LL>0) if (alivecount==1) LogFile::ErrorMessage("(%s) Could not send body to browser\n", ToBrowser.GetIP().c_str());
                return -10;
            }

            //File completely received?
            if ( ContentLength == ContentLengthReference ) break;

            //Read more of body
            if ( (BodyLength = ToServer.ReadBodyPart( &BodyTemp )) < 0 )
            {
                if (LL>0) LogFile::ErrorMessage("(%s) Could not read server body (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
                DropServer = true;
                return -75;
            }

            //Server finished, end loop
            if ( BodyLength == 0 )
            {
                //If we did not receive all data, close all connections
                if ( ContentLength < ContentLengthReference ) DropBrowser = true;

                break;
            }

            ContentLength += BodyLength;

            //Continue bodyloop..
        }

        //Return clean
        return 0;
    }

    //
    // Scanning is needed, so lets go..
    //

    //Read first part of body
    ssize_t BodyLength = ToServer.ReadBodyPart( &BodyTemp );

    //Server disconnected?
    if ( BodyLength < 0 )
    {
        if (LL>0) LogFile::ErrorMessage("(%s) Could not read server body (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
        DropServer = true;
        return -75;
    }

    //Nothing received?
    if ( BodyLength == 0 )
    {
        //Lets be safe and close all connections
        DropBrowser = true;

        //Send header to browser
        if ( ToBrowser.SendHeader( Header, DropBrowser ) == false )
        {
            BrowserDropped = true;
            if (LL>0) LogFile::ErrorMessage("(%s) Could not send header to browser\n", ToBrowser.GetIP().c_str());
            return -10;
        }

        //Return clean
        return 0;
    }

    //Set initial values
    long long ContentLength = BodyLength;
    long long TransferDataLength = BodyLength;

    deque <std::string> BodyQueue;
    deque <std::string>::iterator TransferData;

    bool PartlyUnlock = false;
    bool ReScan = false;

    unsigned int KeepBackBuffer = Params::GetConfigInt("KEEPBACKBUFFER");
    unsigned int KeepBackTime = Params::GetConfigInt("KEEPBACKTIME");
    unsigned int TricklingTime = Params::GetConfigInt("TRICKLING");
    unsigned int MaxScanSize = Params::GetConfigInt("MAXSCANSIZE");

    //Scanner will be used and needs to be reinitialized later
    ScannerUsed = true;

    //No scanner answer yet
    int TempScannerAnswer = -1;

    //Start trickling/keepbacktime
    time_t LastTrickling = time(NULL);
    time_t Now;

    //Allocate file fully now, if we have Content-Length and not over MAXSCANSIZE/MAXFILELOCKSIZE
    if ( (ContentLengthReference > 0) && ((ContentLengthReference < MaxScanSize) || (MaxScanSize == 0)) && (ContentLengthReference < MAXFILELOCKSIZE) )
    {
        //Dynamic scanning
        PartlyUnlock = true;

        if ( VirusScannerT->SetFileSize( ContentLengthReference ) == false )
        {
            LogFile::ErrorMessage("(%s) Could not create tempfile, check disk space! (%lld bytes from %s:%d)\n", ToBrowser.GetIP().c_str(), ContentLengthReference, ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            return -100;
        }
    }

    //Body Scanning/Transfer Loop
    for(;;)
    {
        //If we received more than Content-Length, discard the rest
        if ( (ContentLengthReference > 0) && (ContentLength > ContentLengthReference) )
        {
            BodyTemp.erase( BodyTemp.size() - (ContentLength - ContentLengthReference) );

            TransferDataLength -= (ContentLength - ContentLengthReference);
            ContentLength = ContentLengthReference;

            if (LL>0) LogFile::ErrorMessage("(%s) Server sent more than Content-Length (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());

            //Drop server connection (we can keep browser open)
            DropServer = true;
        }

        //Add bodypart to send queue
        BodyQueue.push_back( BodyTemp );

        //Check if we have exceeded MAXSCANSIZE or MAXFILELOCKSIZE which is hard limit
        if ( (UnlockDone == false) && (((MaxScanSize > 0) && (ContentLength > MaxScanSize)) || (ContentLength > MAXFILELOCKSIZE)) )
        {
            //As we won't be scanning anymore, unlock file and let scanner finish
            VirusScannerT->UnlockFile();
            UnlockDone = true;
        }

        //Expand file if we have not exceeded limits or gotten answer
        if ( (UnlockDone == false) && ( VirusScannerT->ExpandFile( &BodyTemp, PartlyUnlock ) == false ) )
        {
            LogFile::ErrorMessage("(%s) Could not expand tempfile, check disk space! (%lld bytes from %s:%d)\n", ToBrowser.GetIP().c_str(), ContentLengthReference, ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            return -100;
        }

        //Exit bodyloop because file is complete
        if ( ContentLength == ContentLengthReference ) break;

        //Check for possible scanner answer
        if ( PartlyUnlock || UnlockDone )
        {
            if ( (ReinitDone == false) && (VirusScannerT->CheckScanner(false) == 1) )
            {
                AnswerDone = true;

                //Get answer
                if ( (TempScannerAnswer = VirusScannerT->CheckScanner(true)) != 0 )
                {
                    if ( TempScannerAnswer == 2 )
                    {
                        if ( Params::GetConfigBool("FAILSCANERROR") )
                        {
                            //Exit bodyloop if we want scanner errors reported
                            break;
                        }
                        else
                        {
                            //Else pretend we are clean and continue body transfer
                            TempScannerAnswer = 0;
                        }
                    }
                    else
                    {
                        //Exit bodyloop because virus is found
                        break;
                    }
                }

                //Reinitialize tempfile, it is not needed on disk anymore
                VirusScannerT->UnlockFile();
                UnlockDone = true;
                VirusScannerT->ReinitFile();
                ReinitDone = true;
            }
        }

        Now = time(NULL);

        //Wait for KeepBackTime to pass
        if ( (KeepBackTime == 0) || (LastTrickling + KeepBackTime < Now) )
        {
            //Dont check KeepBackTime anymore
            KeepBackTime = 0;

            TransferData = BodyQueue.begin();

            //Send data if we have enough in buffer or scanning was clean
            if ( (TempScannerAnswer == 0) || (KeepBackBuffer < (TransferDataLength - TransferData->length())) )
            {
                //Send header only once
                if ( HeaderSend == false )
                {
                    HeaderSend = true;
                    if ( ToBrowser.SendHeader( Header, DropBrowser ) == false )
                    {
                        BrowserDropped = true;
                        if (LL>0) LogFile::ErrorMessage("(%s) Could not send header to browser\n", ToBrowser.GetIP().c_str());
                        return -10;
                    }
                }

                BodyTemp = *TransferData;
                TransferDataLength -= BodyTemp.length();

                if ( ToBrowser.Send( &BodyTemp ) == false )
                {
                    BrowserDropped = true;
                    if (LL>0) if (alivecount==1) LogFile::ErrorMessage("(%s) Could not send body to browser\n", ToBrowser.GetIP().c_str());
                    return -10;
                }

                BodyQueue.erase( TransferData );
            }
            //Else check trickling
            else if ( (TricklingTime > 0) && (LastTrickling + TricklingTime < Now) )
            {
                //Send header only once
                if ( HeaderSend == false )
                {
                    HeaderSend = true;

                    if ( ToBrowser.SendHeader( Header, DropBrowser ) == false )
                    {
                        BrowserDropped = true;
                        if (LL>0) LogFile::ErrorMessage("(%s) Could not send header to browser\n", ToBrowser.GetIP().c_str());
                        return -10;
                    }
                }

                LastTrickling = Now;

                TransferDataLength -= 1; //send one character

                string character = TransferData->substr(0,1);
                TransferData->erase(0,1);

                if ( TransferData->size() == 0 ) BodyQueue.erase( TransferData );

                if ( ToBrowser.Send( &character ) == false )
                {
                    BrowserDropped = true;
                    if (LL>0) if (alivecount==1) LogFile::ErrorMessage("(%s) Could not send body to browser\n", ToBrowser.GetIP().c_str());
                    return -10;
                }

            }
        }

        //Read more of body
        if ( (BodyLength = ToServer.ReadBodyPart( &BodyTemp )) < 0 )
        {
            if (LL>0) LogFile::ErrorMessage("(%s) Could not read server body (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            DropServer = true;
            return -75;
        }

        ContentLength += BodyLength;
        TransferDataLength += BodyLength;

        //Server finished, end loop
        if ( BodyLength == 0 )
        {
            //If we did not receive all data, close all connections
            if ( ContentLength < ContentLengthReference )
            {
                DropBrowser = true;

                //We need a rescan if no full unlock done yet
                if ( AnswerDone == false ) ReScan = true;
            }
                
            //Exit loop
            break;
        }

        //Continue bodyloop..
    }

    //Close connection to server if needed
    if ( DropServer || DropBrowser )
    {
        ToServer.Close();
        ServerClosed = true;
        ServerConnected = false;
    }

    //Unlock if needed
    if ( UnlockDone == false )
    {
        VirusScannerT->UnlockFile();
        UnlockDone = true;
    }

    //Rescan tempfile if needed
    if ( ReScan )
    {
        //Finish old scan
        VirusScannerT->CheckScanner(true);
        VirusScannerT->ReadScannerAnswer();

        //Truncate file to received size
        VirusScannerT->TruncateFile(ContentLength);

        //Tell scanner to start scanning
        while ((ret = write(VirusScannerT->commout[1], (const char*) "c", 1)) < 0)
        {
            if (errno == EINTR) continue;
            exit(0);
        }
        if (ret == 0) exit(0);

        //Get new answer
        TempScannerAnswer = VirusScannerT->CheckScanner(true);
        AnswerDone = true;
    }

    //Get answer if needed
    if ( AnswerDone == false )
    {
        TempScannerAnswer = VirusScannerT->CheckScanner(true);
        AnswerDone = true;
    }

    //Reinit if needed
    if ( ReinitDone == false )
    {
        VirusScannerT->ReinitFile();
        ReinitDone = true;
    }

    switch ( TempScannerAnswer )
    {
        case 0:

            //Send rest of the data to browser
            if ( HeaderSend == false )
            {
                HeaderSend = true;

                if ( ToBrowser.SendHeader( Header, DropBrowser ) == false )
                {
                    BrowserDropped = true;
                    if (LL>0) LogFile::ErrorMessage("(%s) Could not send header to browser\n", ToBrowser.GetIP().c_str());
                    return -10;
                }
            }

            for ( TransferData = BodyQueue.begin(); TransferData != BodyQueue.end(); ++TransferData )
            {
                BodyTemp = *TransferData;

                if ( ToBrowser.Send( &BodyTemp ) == false )
                {
                    BrowserDropped = true;
                    if (LL>0) if (alivecount==1) LogFile::ErrorMessage("(%s) Could not send body to browser\n", ToBrowser.GetIP().c_str());
                    return -10;
                }
            }

            //Clean
            return 0;

        case 1:

            //Virus
            return 1;

        case 2:

            if ( Params::GetConfigBool("FAILSCANERROR") )
            {
                //Error
                return 2;
            }
            else
            {
                //Return clean if we do not want errors
                return 0;
            }
    }

    //Should never get here..
    return 2;
}


int ProxyHandler::CommunicationFTP( GenericScanner *VirusScannerT, bool ScannerOff )
{
    return 0;
}


#ifdef SSLTUNNEL
int ProxyHandler::CommunicationSSL()
{

    string Header = ToBrowser.PrepareHeaderForServer();

    string parentproxy = Params::GetConfigString("PARENTPROXY");
    int parentport = Params::GetConfigInt("PARENTPORT");

    if ( parentproxy != "" && parentport > 0 )
    {
        if ( ToServer.SetDomainAndPort( parentproxy, parentport ) == false )
        {
            LogFile::ErrorMessage("Could not resolve parent proxy (%s)\n", parentproxy.c_str() );
            return -51;
        }
        if ( ToServer.ConnectToServer() == false )
        {
            LogFile::ErrorMessage("Could not connect to parent proxy (%s:%d)\n", parentproxy.c_str(), parentport);
            return -61;
        }

        if ( ToServer.SendHeader( Header, true ) == false )
        {
            if (LL>0) LogFile::ErrorMessage("Could not send header to server (%s:%d)\n", ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            return -60;
        }

        if ( ToServer.ReadHeader( &Header ) == false )
        {
            if (LL>0) LogFile::ErrorMessage("Could not read server header (%s:%d)\n", ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            return -80;
        }

        if ( Header.substr(9, 3) != "200" )
        {
            if (LL>0) LogFile::ErrorMessage("SSL tunneling failed through parentproxy (response: %s)\n", Header.substr(9, 3).c_str());
            return -300;
        }
    }
    else
    {
        if ( ToServer.SetDomainAndPort( ToBrowser.GetHost(), ToBrowser.GetPort() ) == false )
        {
            if (LL>0) LogFile::ErrorMessage("Could not resolve hostname: %s\n", ToBrowser.GetHost().c_str() );
            return -50;
        }
        if ( ToServer.ConnectToServer() == false )
        {
            if (LL>0) LogFile::ErrorMessage("Could not connect to server (%s:%d)\n", ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            return -60;
        }
    }

    Header = "HTTP/1.0 200 Connection established\r\n";

    if ( ToBrowser.SendHeader( Header, true ) == false )
    {
        BrowserDropped = true;
        if (LL>0) LogFile::ErrorMessage("(%s) Could not send SSL header to browser\n", ToBrowser.GetIP().c_str());
        return -10;
    }

    string BodyTemp;
    ssize_t BodyLength;

    int ret;

    while ( (ret = ToBrowser.CheckForSSLData( ToBrowser.sock_fd, ToServer.sock_fd )) > 0 )
    {
        if ( ret == 2 )
        {
            BodyLength = ToServer.ReadBodyPart( &BodyTemp );
            if ( BodyLength < 1 ) break;
            if ( ToBrowser.Send( &BodyTemp ) == false ) break;
            continue;
        }
        else if ( ret == 1 )
        {
            BodyLength = ToBrowser.ReadBodyPart( &BodyTemp );
            if ( BodyLength < 1 ) break;
            if ( ToServer.Send( &BodyTemp ) == false ) break;
            continue;
        }
    }

    return 0;
}
#endif


bool ProxyHandler::ProxyMessage( int CommunicationAnswerT, string Answer )
{

    string filename = "";
    string message = "";

    switch ( CommunicationAnswerT )
    {
        case -10: //Browser Dropped
            break;

        case -50:
            message = ToBrowser.GetHost();
            filename = ERROR_DNS;
            break;

        case -60:
        case -75:
        case -80:
            message = ToBrowser.GetHost();
            filename = ERROR_DOWN;
            break;

        case -45:
            LogFile::AccessMessage("%s Blacklisted: %s\n", ToBrowser.GetIP().c_str(), ToBrowser.GetCompleteRequest().c_str());
            message = ToBrowser.GetCompleteRequest();
            filename = ERROR_BLACKLIST;
            break;

        case -51:
            message = "Parentproxy did not resolve";
            filename = ERROR_DNS;
            break;

        case -61:
            message = "Parentproxy down";
            filename = ERROR_DOWN;
            break;

        case -100:
            message = "Not enough free space on server";
            filename = ERROR_SCANNER;
            break;

        case -110:
            message = "FTP is currently supported only<br>if PARENTPROXY is used!";
            filename = ERROR_REQUEST;
            break;

        case -201:
            message = "Invalid request";
            filename = ERROR_REQUEST;
            break;

        case -202:
            message = "Invalid request method";
            filename = ERROR_REQUEST;
            break;

        case -210:
            message = "Hostname too long";
            filename = ERROR_REQUEST;
            break;

        case -211:
            message = "Port not allowed";
            filename = ERROR_REQUEST;
            break;

        case -212:
            message = "Invalid port";
            filename = ERROR_REQUEST;
            break;

        case -215:
            message = "Unsupported protocol";
            filename = ERROR_REQUEST;
            break;

        case -220:
            message = "Empty Host-header";
            filename = ERROR_REQUEST;
            break;

        case -230:
            message = "Invalid HTTP response from server";
            filename = ERROR_REQUEST;
            break;

        case -231:
            message = "Server tried to send partial data<br>and RANGE is set to false";
            filename = ERROR_REQUEST;
            break;

#ifdef SSLTUNNEL
        case -300:
            message = "SSL tunneling failed through parentproxy";
            filename = ERROR_REQUEST;
            break;
#endif

        case 1: //Virus
            if ( BrowserDropped )
                LogFile::AccessMessage("%s %s Virus: %s (Browser closed before receiving)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetCompleteRequest().c_str(), Answer.c_str());
            else
                LogFile::AccessMessage("%s %s Virus: %s\n", ToBrowser.GetIP().c_str(), ToBrowser.GetCompleteRequest().c_str(), Answer.c_str());
            message = Answer;
            filename = VIRUS_FOUND;
            break;

        case 2: //Error
            LogFile::AccessMessage("%s %s ScannerError: %s\n", ToBrowser.GetIP().c_str(), ToBrowser.GetCompleteRequest().c_str(), Answer.c_str());
            message = Answer;
            filename = ERROR_SCANNER;
            break;

        default:

            //Log if we have error not defined above.. all should be there!
            LogFile::ErrorMessage("Program Error: Unknown Error %d\n", CommunicationAnswerT);
            char ErrorNumber[11];
            snprintf(ErrorNumber, 10, "%d", CommunicationAnswerT);
            message = ErrorNumber;
            filename = ERROR_BODY;
            break;

    }

    //Check these here so we have logged possible viruses and errors above
    if ( BrowserDropped ) return false;

    //Send report to browser if possible
    if ( HeaderSend == false )
    {
        //Start header
        string errorheader = "HTTP/1.0 ";

        //Create header body
        if ( filename == ERROR_DNS )
        {
            errorheader += "403 DNS error from HAVP";
        }
        else if ( filename == ERROR_DOWN )
        {
            errorheader += "403 Server down from HAVP";
        }
        else if ( filename == ERROR_REQUEST )
        {
            errorheader += "403 Request error from HAVP";
        }
        else if ( filename == VIRUS_FOUND )
        {
            errorheader += "403 Virus " + message + " found";
        }
        else if ( filename == ERROR_SCANNER )
        {
            errorheader += "403 Scanner error from HAVP";
        }
        else if ( filename == ERROR_BLACKLIST )
        {
            errorheader += "403 Blacklisted from HAVP";
        }
        else
        {
            errorheader += "403 Forbidden from HAVP";
        }

        //End header
        errorheader += "\r\nContent-Type: text/html\r\nProxy-Connection: close\r\nConnection: close\r\n\r\n";

        if ( ToBrowser.Send( &errorheader ) == false )
        {
            return false;
        }
    }

    //Send report page, but for HEAD request body is not allowed
    if ( (filename != "") && (ToBrowser.GetRequestType() != "HEAD") )
    {
        string path = Params::GetConfigString("TEMPLATEPATH");
        filename = path + "/" + filename;

        FILE* tfile;

        if ( (tfile = fopen(filename.c_str(), "r")) != NULL )
        {
            char filebuf[STRINGLENGTH+1];
            string Response = "";

            while (!feof(tfile))
            {
                fgets(filebuf, STRINGLENGTH, tfile);
                Response += filebuf;
            }
            fclose(tfile);

            if ( Response != "" )
            {
                SearchReplace( &Response, "<!--message-->", message );
                if ( ToBrowser.Send( &Response ) == false ) BrowserDropped = true;
            } 
        }
        else
        {
            string TemplateError = "HAVP could not open Template! Check errorlog and config!";
            if (ToBrowser.Send( &TemplateError ) == false) BrowserDropped = true;
        }
    }
    
    return false;
}

ProxyHandler::ProxyHandler()
{
}


ProxyHandler::~ProxyHandler()
{
}
