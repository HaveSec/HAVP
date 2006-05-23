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

#include <errno.h>
#include <deque>
#include <iostream>
#include <fstream>

extern URLList Whitelist;
extern URLList Blacklist;
extern int LL; //LogLevel

void ProxyHandler::Proxy( SocketHandler &ProxyServerT, ScannerHandler &Scanners )
{
    extern bool childrestart;

    int ret, CommunicationAnswer;

    bool ScannerOff = false;

    int requests = 0;
    alivecount = 0;

    ServerConnected = BrowserDropped = DropBrowser = false;

    //Wait for first connection
    while ( ProxyServerT.AcceptClient( ToBrowser ) == false ) sleep(10);

    //Infinite Processing Loop
    for(;;)
    {

        ++requests;

        if ( DropBrowser || BrowserDropped )
        {
            //Close browser connection
            ToBrowser.Close();

            //Close server connection
            ToServer.Close();
            ServerConnected = false;

            //Reset keepalive count
            alivecount = 0;

            //Wait for new connection
            while ( ProxyServerT.AcceptClient( ToBrowser ) == false ) sleep(10);
        }

        //Clear request variables
        ToBrowser.ClearVars();
        ToServer.ClearVars();
        ScannerUsed = UnlockDone = AnswerDone = ReinitDone = HeaderSend = BrowserDropped = DropBrowser = DropServer = false;
        TransferredHeader = TransferredBody = 0;

        if ( ++alivecount > 1 )
        {
            //Keep-Alive timeout 10 seconds
            if ( ToBrowser.CheckForData(10) == false )
            {
                DropBrowser = true;
                continue;
            }
        }

        if ( ToBrowser.ReadHeader( Header ) == false )
        {
            if (LL>0) if (alivecount==1) LogFile::ErrorMessage("(%s) Could not read browser header\n", ToBrowser.GetIP().c_str());
            DropBrowser = true;
            continue;
        }

        if ( (ret = ToBrowser.AnalyseHeader( Header )) < 0 )
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
        ToBrowser.PrepareHeaderForServer( false, UseParentProxy );
                ProxyMessage( -45, "" );
                DropBrowser = true;
                continue;
            }
        }

#ifdef SSLTUNNEL
    }
#endif

        //Keep-Alive?
        if ( ToBrowser.KeepItAlive() == false || ToBrowser.GetRequestType() != "GET" || ( (alivecount > 99) && (ToBrowser.CheckForData(0) == false) ) )
        {
            DropBrowser = true;
        }

        //HTTP REQUEST
        if ( ToBrowser.GetRequestProtocol() == "http" )
        {
            CommunicationAnswer = CommunicationHTTP( Scanners, ScannerOff );
        }
        //FTP REQUEST
        else if ( ToBrowser.GetRequestProtocol() == "ftp" )
        {
            if ( UseParentProxy )
            {
                CommunicationAnswer = CommunicationHTTP( Scanners, ScannerOff );
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
            ToServer.Close();

            CommunicationAnswer = CommunicationSSL();

            //Close connection
            ToServer.Close();
            ServerConnected = false;

            if ( CommunicationAnswer != 0 ) ProxyMessage( CommunicationAnswer, "" );

            DropBrowser = true;
            continue;
        }
#endif
        else
        {
            LogFile::ErrorMessage("Program Error: Unsupported RequestProtocol: %s\n", ToBrowser.GetRequestProtocol().c_str());
            DropBrowser = true;
            continue;
        }


        //Retry GET connection once if ReadHeader error (-80) or Connect error (-60, -61)
        //Also reconnect if server closed Keep-Alive connection (-60)
        if ( (CommunicationAnswer == -80 && ToBrowser.GetRequestType() == "GET") || CommunicationAnswer == -60 || CommunicationAnswer == -61 )
        {
            ToServer.Close();
            ServerConnected = false;

            //Sleep second before retry
            sleep(1);

            CommunicationAnswer = CommunicationHTTP( Scanners, ScannerOff );

            //No need to stop Keep-Alive if retry is clean
            if ( CommunicationAnswer == 0 ) DropServer = false;
        }

        //Make sure server connection is closed if needed
        if ( DropServer || DropBrowser || BrowserDropped )
        {
            ToServer.Close();
            ServerConnected = false;
        }

        //Check scanners
        if ( ScannerUsed )
        {
#ifndef NOMAND
            if ( UnlockDone == false ) Scanners.UnlockTempFile();
#endif
            if ( AnswerDone == false ) Scanners.GetAnswer();
        }

        if ( CommunicationAnswer != 0 )
        {
            //Request not clean
            ProxyMessage( CommunicationAnswer, Scanners.GetAnswerMessage() );
            DropBrowser = true;
        }
        else if ( Params::GetConfigBool("LOG_OKS") )
        {
            //Clean request
            LogFile::AccessMessage("%s %s %d %s %d+%lld OK\n", ToBrowser.GetIP().c_str(), ToBrowser.GetRequestType().c_str(), ToServer.GetResponse(), ToBrowser.GetCompleteRequest().c_str(), TransferredHeader, TransferredBody);
        }

        //If some scanner timed out, bail out..
        if ( CommunicationAnswer == 3 ) break;

        //Signal scanners
        if ( ScannerUsed )
        {
            //Exit processes if restart signaled or maximum reqs reached
            if ( (DropBrowser || BrowserDropped) && (childrestart || (requests > 1000)) )
            {
                //Kill all scanners
                Scanners.ExitScanners();

                //Exit processing loop
                break;
            }

            //Reinit tempfile
            if ( ReinitDone == false ) Scanners.ReinitTempFile();

            //Signal scanners to get ready again
            if ( Scanners.RestartScanners() == false )
            {
                //Some scanner did not restart, exit processing loop
                break;
            }
        }

    }

    //Make sure browser connection is closed
    ToBrowser.Close();

    //Delete Tempfile
    Scanners.DeleteTempFile();

    //Exit process
    exit(1);
}


int ProxyHandler::CommunicationHTTP( ScannerHandler &Scanners, bool ScannerOff )
{

    long long ContentLengthReference = ToBrowser.GetContentLength();

    //Check that POST has Content-Length
    if ( (ToBrowser.GetRequestType() == "POST") && (ContentLengthReference == -1) )
    {
        BrowserDropped = true;
        LogFile::ErrorMessage("(%s) Browser POST without Content-Length header\n", ToBrowser.GetIP().c_str());
        return -10;
    }

    //Make server connection
    if ( UseParentProxy )
    {
        if ( ServerConnected == false )
        {
            if ( ToServer.SetDomainAndPort( ParentHost, ParentPort ) == false )
            {
                LogFile::ErrorMessage("Could not resolve parent proxy (%s)\n", ParentHost.c_str());
                return -51;
            }
            if ( ToServer.ConnectToServer() == false )
            {
                LogFile::ErrorMessage("Could not connect to parent proxy (%s:%d)\n", ParentHost.c_str(), ParentPort);
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

    Header = ToBrowser.PrepareHeaderForServer( ScannerOff, UseParentProxy );

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

                    if ( ToBrowser.RecvLength( Body, rest ) == false )
                    {
                        BrowserDropped = true;
                        if (LL>0) LogFile::ErrorMessage("(%s) Could not read browser body\n", ToBrowser.GetIP().c_str());
                        return -10;
                    }
                }
                else
                {
                    if ( ToBrowser.RecvLength( Body, MAXRECV ) == false )
                    {
                        BrowserDropped = true;
                        if (LL>0) LogFile::ErrorMessage("(%s) Could not read browser body\n", ToBrowser.GetIP().c_str());
                        return -10;
                    }
                }

                if ( ToServer.Send( Body ) == false )
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

            if ( ToBrowser.Recv( TempString, true, -1 ) < 0 )
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
    if ( ToServer.ReadHeader( Header ) == false )
    {
        if (LL>0) LogFile::ErrorMessage("(%s) Could not read server header (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
        DropServer = true;
        return -80;
    }

    TransferredHeader = Header.size();

    //Analyse server headers
    int ret = ToServer.AnalyseHeader( Header );
    if ( ret < 0 )
    {
        if (LL>0) LogFile::ErrorMessage("(%s) Invalid server header received (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
        DropServer = true;
        return ret;
    }

    //Check if server sent partial response when not allowed
    if ( (ToServer.GetResponse() == 206) && (Params::GetConfigBool("RANGE") == false) )
    {
        //If whitelisted or streaming User-Agent, we do allow partial
        if ( (ScannerOff == false) && ( ToBrowser.StreamingAgent() == false) )
        {
            if (LL>0) LogFile::ErrorMessage("(%s) Server tried to send partial data and RANGE set to false (%s:%d)\n", ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            DropServer = true;
            return -231;
        }
    }

    //Server did not send Keep-Alive header, close after request (we can keep browser open)
    if ( ToServer.KeepItAlive() == false ) DropServer = true;

    //Get Content-Length
    ContentLengthReference = ToServer.GetContentLength();

    if ( ContentLengthReference == -1 )
    {
        //No Keep-Alive for unknown length
        DropBrowser = true;
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
            ssize_t BodyLength = ToServer.Recv( BodyTemp, true, -1 );
            if ( (BodyLength > 0) && (BodyTemp.find_first_not_of( "\r\n", 0 ) != string::npos) )
            {
                LogFile::ErrorMessage("(%s) Server tried to send body when not expected (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
                DropServer = true;
            }
        }

        //Return clean
        return 0;
    }

    if ( (ContentLengthReference > 0) && (ContentLengthReference < 10) )
    {
        //Forget scanning for tiny files
        ScannerOff = true;
    }
    else if ( (MaxDownloadSize != 0) && (ScannerOff == false) && (MaxDownloadSize < ContentLengthReference) )
    {
        //File too large for downloading
        DropServer = true;
        return -250;
    }

    unsigned int MaxScanSize = Params::GetConfigInt("MAXSCANSIZE");
    
    //For streaming User-Agents, check if we need scanning
    if ( ToBrowser.StreamingAgent() )
    {
        if ( Params::GetConfigInt("STREAMSCANSIZE") > 0 )
        {
            MaxScanSize = Params::GetConfigInt("STREAMSCANSIZE");
        }
        else
        {
            ScannerOff = true;
        }
    }

    //If scanning is not needed, use this quick send loop
    if ( ScannerOff )
    {
        //Read first part of body
        string BodyTemp;
        ssize_t BodyLength = ToServer.ReadBodyPart( BodyTemp );

        //Server disconnected?
        if ( BodyLength < 0 )
        {
            DropServer = true;
            if (LL>0) LogFile::ErrorMessage("(%s) Could not read server body (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
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
        TransferredBody = ContentLength;

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
            if ( ToBrowser.Send( BodyTemp ) == false )
            {
                BrowserDropped = true;
                if (LL>0) if (alivecount==1) LogFile::ErrorMessage("(%s) Could not send body to browser\n", ToBrowser.GetIP().c_str());
                return -10;
            }

            //File completely received?
            if ( ContentLength == ContentLengthReference ) break;

            //Read more of body
            if ( (BodyLength = ToServer.ReadBodyPart( BodyTemp )) < 0 )
            {
                DropServer = true;
                if (LL>0) LogFile::ErrorMessage("(%s) Could not read server body (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
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
            TransferredBody = ContentLength;

            //Continue bodyloop..
        }

        //Return clean
        return 0;
    }

    //
    // Scanning is needed, so lets go..
    //

    //Read first part of body
    string BodyTemp;
    ssize_t BodyLength = ToServer.ReadBodyPart( BodyTemp );

    //Server disconnected?
    if ( BodyLength < 0 )
    {
        DropServer = true;
        if (LL>0) LogFile::ErrorMessage("(%s) Could not read server body (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
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
    TransferredBody = ContentLength;
    long long TransferDataLength = BodyLength;

    deque <std::string> BodyQueue;
    deque <std::string>::iterator TransferData;

    bool PartlyUnlock = false;
    bool ReScan = false;

#ifndef NOMAND
    bool NoKeepBack = false;
#endif

    //Scanner will be used and needs to be reinitialized later
    ScannerUsed = true;

    //No scanners answer yet
    int TempScannerAnswer = -1;

    //Start trickling/keepbacktime
    time_t LastTrickling = time(NULL);
    time_t Now;

    //Allocate file fully now, if we have Content-Length and not over MAXSCANSIZE/MAXFILELOCKSIZE
    if ( (ContentLengthReference > 0) && ((ContentLengthReference < MaxScanSize) || (MaxScanSize == 0)) && (ContentLengthReference < MAXFILELOCKSIZE) )
    {
        //Dynamic scanning
        PartlyUnlock = true;

        if ( Scanners.SetTempFileSize( ContentLengthReference ) == false )
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
#ifndef NOMAND
            //As we won't be scanning anymore, unlock file and let scanners finish
            Scanners.UnlockTempFile();
            UnlockDone = true;
#else
            //Check answers
            TempScannerAnswer = Scanners.GetAnswer();
            Scanners.ReinitTempFile();

            AnswerDone = UnlockDone = true;

            //Exit bodyloop if error or virus found
            if ( TempScannerAnswer != 0 ) break;
#endif
        }

        //Expand file if we have not exceeded limits or gotten answer
        if ( (UnlockDone == false) && ( Scanners.ExpandTempFile( BodyTemp, PartlyUnlock ) == false ) )
        {
            LogFile::ErrorMessage("(%s) Could not expand tempfile, check disk space! (%lld bytes from %s:%d)\n", ToBrowser.GetIP().c_str(), ContentLengthReference, ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            return -100;
        }

        //Exit bodyloop because file is complete
        if ( ContentLength == ContentLengthReference ) break;

#ifndef NOMAND
        //Check for possible scanners answer
        if ( (PartlyUnlock || UnlockDone) && (ReinitDone == false) )
        {
            if ( Scanners.HasAnswer() )
            {
                AnswerDone = true;

                //Unlock file now so all scanners can finish
                if ( UnlockDone == false )
                {
                    Scanners.UnlockTempFile();
                    UnlockDone = true;
                }

                //Get Answer
                TempScannerAnswer = Scanners.GetAnswer();

                //Exit bodyloop if virus or error found!
                if ( TempScannerAnswer != 0 ) break;

                //Reinitialize tempfile, it is not needed on disk anymore
                Scanners.ReinitTempFile();
                ReinitDone = true;

                //Continue bodyloop so browser receives all data
            }
        }
#endif

        Now = time(NULL);

#ifdef NOMAND
            //Send data if scanning was clean
            if ( TempScannerAnswer == 0 )
            {

                TransferData = BodyQueue.begin();
#else
        //Wait for KeepBackTime to pass
        if ( NoKeepBack || (LastTrickling + KeepBackTime < Now) )
        {
            //Dont check KeepBackTime anymore
            NoKeepBack = true;

            TransferData = BodyQueue.begin();

            //Send data if we have enough in buffer or scanning was clean
            if ( (TempScannerAnswer == 0) || (KeepBackBuffer < (TransferDataLength - TransferData->size())) )
            {
#endif
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
                TransferDataLength -= BodyTemp.size();

                if ( ToBrowser.Send( BodyTemp ) == false )
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

                if ( ToBrowser.Send( character ) == false )
                {
                    BrowserDropped = true;
                    if (LL>0) if (alivecount==1) LogFile::ErrorMessage("(%s) Could not send body to browser\n", ToBrowser.GetIP().c_str());
                    return -10;
                }
            }
#ifndef NOMAND
        }
#endif

        //Read more of body
        if ( (BodyLength = ToServer.ReadBodyPart( BodyTemp )) < 0 )
        {
            DropServer = true;
            if (LL>0) LogFile::ErrorMessage("(%s) Could not read server body (%s:%d)\n", ToBrowser.GetIP().c_str(), ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            return -75;
        }

        ContentLength += BodyLength;
        TransferredBody = ContentLength;
        TransferDataLength += BodyLength;

        //Check if file is too large for downloading
        if ( (MaxDownloadSize != 0) && (ContentLength > MaxDownloadSize) )
        {
            DropServer = true;
            return -250;
        }

        //Server finished, end bodyloop
        if ( BodyLength == 0 )
        {
            //If we did not receive all data, close all connections
            if ( ContentLength < ContentLengthReference )
            {
                DropBrowser = true;

                //We need a rescan if no full unlock done yet
                if ( AnswerDone == false ) ReScan = true;
            }
                
            //Exit bodyloop
            break;
        }

        //Continue bodyloop..
    }

    //Close connection to server if needed
    if ( DropServer || DropBrowser )
    {
        ToServer.Close();
        ServerConnected = false;
    }

#ifndef NOMAND
    //Unlock if needed
    if ( UnlockDone == false )
    {
        Scanners.UnlockTempFile();
        UnlockDone = true;
    }
#endif

    //Get answer if needed
    if ( AnswerDone == false )
    {
#ifdef NOMAND
        //Truncate file to received size
        if ( ReScan ) Scanners.TruncateTempFile( ContentLength );
#endif
        TempScannerAnswer = Scanners.GetAnswer();
        AnswerDone = true;
    }

#ifndef NOMAND
    //Rescan tempfile if we didn't receive all Content-Length
    //It might have confused scanners with wrong filesize
    if ( ReScan && (TempScannerAnswer != 1) )
    {
        //Truncate file to received size
        Scanners.TruncateTempFile( ContentLength );

        //Tell scanners to start scanning again
        if ( Scanners.RestartScanners() == false )
        {
            //Bail out on error..
            ToBrowser.Close();
            Scanners.DeleteTempFile();
            exit(1);
        }

        //Get new answer
        TempScannerAnswer = Scanners.GetAnswer();
        AnswerDone = true;
    }
#endif

    //Reinit if needed
    if ( ReinitDone == false )
    {
        Scanners.ReinitTempFile();
        ReinitDone = true;
    }

    //Virus or error?
    if ( TempScannerAnswer != 0 ) return TempScannerAnswer;

    //Send remaining data to browser
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

        if ( ToBrowser.Send( BodyTemp ) == false )
        {
            BrowserDropped = true;
            if (LL>0) if (alivecount==1) LogFile::ErrorMessage("(%s) Could not send body to browser\n", ToBrowser.GetIP().c_str());
            return -10;
        }
    }

    //Return clean
    return 0;
}


//Not yet implemented..
int ProxyHandler::CommunicationFTP( ScannerHandler &Scanners, bool ScannerOff )
{
    return 0;
}


#ifdef SSLTUNNEL
int ProxyHandler::CommunicationSSL()
{
    string BodyTemp;
    ssize_t BodyLength;

    Header = ToBrowser.PrepareHeaderForServer( false, UseParentProxy );

    if ( UseParentProxy )
    {
        if ( ToServer.SetDomainAndPort( ParentHost, ParentPort ) == false )
        {
            LogFile::ErrorMessage("Could not resolve parent proxy (%s)\n", ParentHost.c_str() );
            return -51;
        }
        if ( ToServer.ConnectToServer() == false )
        {
            LogFile::ErrorMessage("Could not connect to parent proxy (%s:%d)\n", ParentHost.c_str(), ParentPort);
            return -61;
        }

        if ( ToServer.SendHeader( Header, true ) == false )
        {
            if (LL>0) LogFile::ErrorMessage("Could not send header to server (%s:%d)\n", ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            return -60;
        }

        if ( ToServer.ReadHeader( Header ) == false )
        {
            if (LL>0) LogFile::ErrorMessage("Could not read server header (%s:%d)\n", ToBrowser.GetHost().c_str(), ToBrowser.GetPort());
            DropServer = true;
            return -80;
        }

        string::size_type Position = Header.find_first_of("0123456789", Header.find(" "));

        if ( Position == string::npos )
        {
            if (LL>0) LogFile::ErrorMessage("Invalid HTTP response from parent proxy to SSL tunnel\n");
            return -300;
        }

        //If response not 200, we have some error from parent proxy
        if ( Header.substr(Position, 3) != "200" )
        {
            //Send header to browser
            if ( ToBrowser.SendHeader( Header, true ) == false )
            {
                BrowserDropped = true;
                if (LL>0) LogFile::ErrorMessage("(%s) Could not send header to browser\n", ToBrowser.GetIP().c_str());
                return -10;
            }

            long long ContentLengthReference = ToServer.GetContentLength();

            //No body expected?
            if ( ContentLengthReference == 0 ) return 0;

            long long ContentLength = 0;

            //Server Body Transfer Loop
            for(;;)
            {
                //Read Body
                if ( (BodyLength = ToServer.ReadBodyPart( BodyTemp )) < 0 )
                {
                    if (LL>0) LogFile::ErrorMessage("(%s) Could not read server body (%s:%d)\n", ToBrowser.GetIP().c_str(), ParentHost.c_str(), ParentPort);
                    DropServer = true;
                    return -75;
                }

                //If server finished, exit loop
                if ( BodyLength == 0 ) break;

                ContentLength += BodyLength;
                TransferredBody = ContentLength;

                //If we received more than Content-Length, discard the rest
                if ( (ContentLengthReference > 0) && (ContentLength > ContentLengthReference) )
                {
                    BodyTemp.erase( BodyTemp.size() - (ContentLength - ContentLengthReference) );

                    ContentLength = ContentLengthReference;

                    if (LL>0) LogFile::ErrorMessage("(%s) Server sent more than Content-Length (%s:%d)\n", ToBrowser.GetIP().c_str(), ParentHost.c_str(), ParentPort);
                }

                //Send body to browser
                if ( ToBrowser.Send( BodyTemp ) == false )
                {
                    BrowserDropped = true;
                    if (LL>0) if (alivecount==1) LogFile::ErrorMessage("(%s) Could not send body to browser\n", ToBrowser.GetIP().c_str());
                    return -10;
                }

                //File completely received?
                if ( ContentLength == ContentLengthReference ) break;
            }
            
            if (LL>0) LogFile::ErrorMessage("(%s) SSL tunneling failed through parentproxy (response: %s)\n", ToBrowser.GetIP().c_str(), Header.substr(Position, 3).c_str());
            return 0;
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

    int ret;

    while ( (ret = ToBrowser.CheckForSSLData( ToBrowser.sock_fd, ToServer.sock_fd )) > 0 )
    {
        if ( ret == 2 )
        {
            BodyLength = ToServer.ReadBodyPart( BodyTemp );
            if ( BodyLength < 1 ) break;
            if ( ToBrowser.Send( BodyTemp ) == false ) break;
            continue;
        }
        else if ( ret == 1 )
        {
            BodyLength = ToBrowser.ReadBodyPart( BodyTemp );
            if ( BodyLength < 1 ) break;
            if ( ToServer.Send( BodyTemp ) == false ) break;
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
            if ( Params::GetConfigBool("LOG_OKS") )
            {
                LogFile::AccessMessage("%s %s %d %s %d+%lld OK\n", ToBrowser.GetIP().c_str(), ToBrowser.GetRequestType().c_str(), ToServer.GetResponse(), ToBrowser.GetCompleteRequest().c_str(), TransferredHeader, TransferredBody);
            }
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
            LogFile::AccessMessage("%s %s %d %s %d+%lld BLACKLIST\n", ToBrowser.GetIP().c_str(), ToBrowser.GetRequestType().c_str(), ToServer.GetResponse(), ToBrowser.GetCompleteRequest().c_str(), TransferredHeader, TransferredBody);
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

        case -230:
            message = "Invalid HTTP response from server";
            filename = ERROR_REQUEST;
            break;

        case -231:
            message = "Server tried to send partial data<br>and RANGE is set to false";
            filename = ERROR_REQUEST;
            break;

        case -250: //File larger than MAXDOWNLOADSIZE
            LogFile::AccessMessage("%s %s %d %s %d+%lld OVERMAXSIZE\n", ToBrowser.GetIP().c_str(), ToBrowser.GetRequestType().c_str(), ToServer.GetResponse(), ToBrowser.GetCompleteRequest().c_str(), TransferredHeader, TransferredBody);
            message = ToBrowser.GetCompleteRequest();
            filename = ERROR_MAXSIZE;
            break;

#ifdef SSLTUNNEL
        case -300:
            message = "SSL tunneling failed through parentproxy";
            filename = ERROR_REQUEST;
            break;
#endif

        case 1: //Virus
            LogFile::AccessMessage("%s %s %d %s %d+%lld VIRUS %s\n", ToBrowser.GetIP().c_str(), ToBrowser.GetRequestType().c_str(), ToServer.GetResponse(), ToBrowser.GetCompleteRequest().c_str(), TransferredHeader, TransferredBody, Answer.c_str());
            SearchReplace( Answer, ", ", "<BR>" );
            message = Answer;
            filename = VIRUS_FOUND;
            break;

        case 2: //Error
        case 3: //Scanner timeout
            LogFile::AccessMessage("%s %s %d %s %d+%lld SCANERROR %s\n", ToBrowser.GetIP().c_str(), ToBrowser.GetRequestType().c_str(), ToServer.GetResponse(), ToBrowser.GetCompleteRequest().c_str(), TransferredHeader, TransferredBody, Answer.c_str());
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
        string UA = ToBrowser.GetUserAgent();
        string Code;

        //IE and Show friendly HTTP errors :(
        if ( UA.find("MSIE") != string::npos )
        {
            Code = "200";
        }
        else
        {
            Code = "403";
        }

        //Start header
        string errorheader = "HTTP/1.0 " + Code + " ";

        //Create header body
        if ( filename == ERROR_DNS )
        {
            errorheader += "DNS error by HAVP";
        }
        else if ( filename == ERROR_DOWN )
        {
            errorheader += "Server down by HAVP";
        }
        else if ( filename == ERROR_REQUEST )
        {
            errorheader += "Request error by HAVP";
        }
        else if ( filename == VIRUS_FOUND )
        {
            errorheader += "Virus found by HAVP";
        }
        else if ( filename == ERROR_SCANNER )
        {
            errorheader += "Scanner error by HAVP";
        }
        else if ( filename == ERROR_BLACKLIST )
        {
            errorheader += "Blacklisted by HAVP";
        }
        else
        {
            errorheader += "Forbidden by HAVP";
        }

        //End header
        errorheader += "\r\nContent-Type: text/html\r\nProxy-Connection: close\r\nConnection: close\r\n\r\n";

        if ( ToBrowser.Send( errorheader ) == false )
        {
            return false;
        }
    }

    //Send report page, but for HEAD request body is not allowed
    if ( (filename != "") && (ToBrowser.GetRequestType() != "HEAD") )
    {
        string path = Params::GetConfigString("TEMPLATEPATH");
        filename = path + "/" + filename;

        ifstream tfile( filename.c_str() );

        if ( !tfile )
        {
            string TemplateError = "HAVP could not open Template! Check errorlog and config!";
            if ( ToBrowser.Send( TemplateError ) == false ) BrowserDropped = true;

            return false;
        }

        string Response = "";
        string Buffer;

        while ( getline( tfile, Buffer ) )
        {
            Response += Buffer;
        }

        tfile.close();

        if ( Response != "" )
        {
            SearchReplace( Response, "<!--message-->", message );
            if ( ToBrowser.Send( Response ) == false ) BrowserDropped = true;
        } 
    }
    
    return false;
}


//Constructor
ProxyHandler::ProxyHandler()
{
    if ( Params::GetConfigString("PARENTPROXY") != "" )
    {
        UseParentProxy = true;
        ParentHost = Params::GetConfigString("PARENTPROXY");
        ParentPort = Params::GetConfigInt("PARENTPORT");
    }
    else
    {
        UseParentProxy = false;
    }

    MaxDownloadSize = Params::GetConfigInt("MAXDOWNLOADSIZE");
    KeepBackTime = Params::GetConfigInt("KEEPBACKTIME");
    TricklingTime = Params::GetConfigInt("TRICKLING");
    KeepBackBuffer = Params::GetConfigInt("KEEPBACKBUFFER");

    Header.reserve(20000);
}


//Destructor
ProxyHandler::~ProxyHandler()
{
}

