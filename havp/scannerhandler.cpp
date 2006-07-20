/***************************************************************************
                          scannerhandler.cpp  -  description
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

#include "default.h"
#include "scannerhandler.h"
#include "logfile.h"
#include "helper.h"
#include "utils.h"

//SCANNERS
#ifdef USECLAMLIB
#include "scanners/clamlibscanner.h"
#endif
#ifdef USETROPHIE
#include "scanners/trophiescanner.h"
#endif
#include "scanners/kasperskyscanner.h"
#include "scanners/avgscanner.h"
#include "scanners/f-protscanner.h"
#include "scanners/nod32scanner.h"
#include "scanners/clamdscanner.h"
#include "scanners/sophiescanner.h"
#include "scanners/avastscanner.h"

#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

extern char TempFileName[MAXSCANTEMPFILELENGTH+1];
extern int fd_tempfile;

//Initialize scanners and load databases
bool ScannerHandler::InitScanners()
{
    //SCANNERS
    if ( Params::GetConfigBool("ENABLECLAMLIB") )
    {
#ifdef USECLAMLIB
        VirusScanner.push_back(new ClamLibScanner);
#else
        LogFile::ErrorMessage("ERROR: HAVP not compiled with ClamAV support\n");
        return false;
#endif
    }
    if ( Params::GetConfigBool("ENABLECLAMD") )
    {
        VirusScanner.push_back(new ClamdScanner);
    }
    if ( Params::GetConfigBool("ENABLETROPHIE") )
    {
#ifdef USETROPHIE
        VirusScanner.push_back(new TrophieScanner);
#else
        LogFile::ErrorMessage("ERROR: HAVP not compiled with Trophie support\n");
        return false;
#endif
    }
    if ( Params::GetConfigBool("ENABLEAVESERVER") )
    {
        VirusScanner.push_back(new KasperskyScanner);
    }
    if ( Params::GetConfigBool("ENABLEAVG") )
    {
        VirusScanner.push_back(new AVGScanner);
    }
    if ( Params::GetConfigBool("ENABLENOD32") )
    {
        VirusScanner.push_back(new NOD32Scanner);
    }
    if ( Params::GetConfigBool("ENABLEFPROT") )
    {
        VirusScanner.push_back(new FProtScanner);
    }
    if ( Params::GetConfigBool("ENABLESOPHIE") )
    {
        VirusScanner.push_back(new SophieScanner);
    }
    if ( Params::GetConfigBool("ENABLEAVAST") )
    {
        VirusScanner.push_back(new AvastScanner);
    }

    if ( VirusScanner.size() == 0 )
    {
        LogFile::ErrorMessage("ERROR: No scanners are enabled in config!\n");
        return false;
    }

    for ( unsigned int i = 0; i < VirusScanner.size(); i++ )
    {
        string Name = VirusScanner[i]->ScannerName;

        LogFile::ErrorMessage("--- Initializing %s\n", Name.c_str());

        if ( VirusScanner[i]->InitDatabase() == false )
        {
            LogFile::ErrorMessage("Error initializing %s!\n", Name.c_str());
            return false;
        }

        //Test scanner with EICAR data (left to TempFileName from hardlock test!!)
        string Answer = VirusScanner[i]->Scan( TempFileName );

        //Make sure we close scanners persistent socket now, because we fork later!
        //Only really needed for Kaspersky at the moment..
        VirusScanner[i]->CloseSocket();

        if ( Answer.substr(0,1) == "1" )
        {
            LogFile::ErrorMessage("%s passed EICAR virus test (%s)\n", Name.c_str(), Answer.substr(1).c_str());
        }
        else
        {
            LogFile::ErrorMessage("ERROR: %s failed EICAR virus test! (%s)\n", Name.c_str(), Answer.substr(1).c_str());
            return false;
        }
    }

    LogFile::ErrorMessage("--- All scanners initialized\n");

    return true;
}


//Fork all scanners, each gets a pipepair for communication
bool ScannerHandler::CreateScanners( SocketHandler &ProxyServerT )
{
    int ret;

    for ( unsigned int i = 0; i < VirusScanner.size(); i++ )
    {
        int sh_to_sc[2];
        int sc_to_sh[2];

        //Create pipes
        if ((ret = pipe(sh_to_sc)) < 0)
        {
            LogFile::ErrorMessage("Scanner pipe creation failed: %s\n", strerror(ret));
            return false;
        }
        if ((ret = pipe(sc_to_sh)) < 0)
        {
            LogFile::ErrorMessage("Scanner pipe creation failed: %s\n", strerror(ret));
            return false;
        }

        //Fork the scanner
        pid_t scannerpid = fork();

        if ( scannerpid < 0 )
        {
            LogFile::ErrorMessage("Could not fork Scanner: %s\n", strerror(errno));
            return false;
        }
        else if ( scannerpid == 0 ) //Scanner child
        {
            //Install Scanner Signals
            if (InstallSignal(2) < 0)
            {
                LogFile::ErrorMessage("Could not install Scanner signal handler\n");
                exit(1);
            }

            //Small sanity check
            if ( fd_tempfile == -1 )
            {
                LogFile::ErrorMessage("Program Error: Scannerchild fd_tempfile == -1\n");
                exit(1);
            }

            //Close ProxyHandler used socket
            ProxyServerT.Close();

            //We don't need tempfile descriptor here anymore, ProxyHandler uses it
            while (close(fd_tempfile) < 0)
            {
                if (errno == EINTR) continue;

                LogFile::ErrorMessage("ScannerHandler could not close() tempfile: %s\n", strerror(errno));
                exit(1);
            }
            fd_tempfile = -1;

            //Close pipe ends that are not needed
            while (close(sh_to_sc[1]) < 0)
            {
                if (errno == EINTR) continue;

                LogFile::ErrorMessage("Could not close scanner pipe: %s\n", strerror(errno));
                exit(1);
            }
            while (close(sc_to_sh[0]) < 0)
            {
                if (errno == EINTR) continue;

                LogFile::ErrorMessage("Could not close scanner pipe: %s\n", strerror(errno));
                exit(1);
            }

            //Enter scanning loop, pass used pipe fds and filename
            VirusScanner[i]->StartScanning( sh_to_sc[0], sc_to_sh[1], TempFileName );

            //Finish child
            exit(1);
        }
        else //Parent = ProxyHandler
        {
            //Struct to hold pipe fds and connected scanners name and pid
            scanner_st scanner_info = { sh_to_sc[1], sc_to_sh[0], VirusScanner[i]->ScannerName, VirusScanner[i]->ScannerNameShort, scannerpid };

            //Add info to list
            Scanner.push_back(scanner_info);

            //Close pipe ends that are not needed
            while (close(sh_to_sc[0]) < 0)
            {
                if (errno == EINTR) continue;

                LogFile::ErrorMessage("Could not close scanner pipe: %s\n", strerror(errno));
                exit(1);
            }
            while (close(sc_to_sh[1]) < 0)
            {
                if (errno == EINTR) continue;

                LogFile::ErrorMessage("Could not close scanner pipe: %s\n", strerror(errno));
                exit(1);
            }
        }
    }

    //Cache some values
    totalscanners = Scanner.size();
    top_fd = 0;

    //Get top descriptor for select
    for ( int i = 0; i < totalscanners; i++ )
    {
        if ( Scanner[i].fromscanner > top_fd )
        {
            top_fd = Scanner[i].fromscanner;
        }
    }

    FD_ZERO(&readfds);
    FD_ZERO(&origfds);
    FD_ZERO(&scannerfds);

    //Set main descriptor list
    for ( int i = 0; i < totalscanners; i++ )
    {
        FD_SET(Scanner[i].fromscanner,&origfds);
    }

    //Set descriptors
    readfds = scannerfds = origfds;

    //Cache zero timeout for select
    memset(&ZeroTimeout, 0, sizeof(ZeroTimeout));
    ZeroTimeout.tv_sec = 0;
    ZeroTimeout.tv_usec = 0;

    //No scanners responded yet
    answers = 0;

    //No virus found yet
    VirusMsg.clear();
    ErrorMsg.clear();

    return true;
}


//Reload scanner databases
//Called from main HAVP process only!
bool ScannerHandler::ReloadDatabases()
{
    bool reloaded = false;

    for ( unsigned int i = 0; i < VirusScanner.size(); i++ )
    {
        if ( VirusScanner[i]->ReloadDatabase() == true )
        {
            reloaded = true;
        }
    }

    return reloaded;
}


//Tell all scanners to start scanning again
bool ScannerHandler::RestartScanners()
{
    int ret;

    for ( int i = 0; i < totalscanners; i++ )
    {
        while ((ret = write(Scanner[i].toscanner, (const char*)"c", 1)) < 0 && errno == EINTR);

        if (ret <= 0)
        {
            LogFile::ErrorMessage("Detected dead %s process\n", Scanner[i].scanner_name.c_str());
            return false;
        }
    }

    //Set descriptors
    readfds = scannerfds = origfds;

    //No scanners responded yet
    answers = 0;

    //Empty message
    VirusMsg.clear();
    ErrorMsg.clear();

    return true;
}


//Tell all scanners to exit
void ScannerHandler::ExitScanners()
{
    int ret;

    for ( int i = 0; i < totalscanners; i++ )
    {
        while ((ret = write(Scanner[i].toscanner, (const char*)"q", 1)) < 0 && errno == EINTR);

        if (ret <= 0)
        {
            LogFile::ErrorMessage("Detected dead %s process\n", Scanner[i].scanner_name.c_str());
        }
    }
}


#ifndef NOMAND
//This check is used only while BodyLoop is running
//If we return true here, BodyLoop will call GetAnswer()
bool ScannerHandler::HasAnswer()
{
    //Set remaining scanners
    readfds = scannerfds;

    //Check if any scanner has answer
    int ret = select_eintr(top_fd+1, &readfds, NULL, NULL, &ZeroTimeout);

    //No scanner ready, BodyLoop can continue!
    if ( ret < 1 ) return false;

    char buf[100];

    //Check all descriptors for answer
    for ( int i = 0; i < totalscanners; i++ )
    {
        //Check if this scanner has answer
        if ( FD_ISSET(Scanner[i].fromscanner,&readfds) )
        {
            //We have one answer more!
            ++answers;

            //Remove scanner from list of checked fds
            FD_CLR(Scanner[i].fromscanner,&scannerfds);

            //Lets be safe
            memset(&buf, 0, sizeof(buf));

            //Read scanner answer
            while ((ret = read(Scanner[i].fromscanner, buf, 100)) < 0 && errno == EINTR);

            if (ret <= 0) //Pipe was closed - or some bad error
            {
                LogFile::ErrorMessage("Detected dead %s process\n", Scanner[i].scanner_name.c_str());

                ErrorMsg.push_back( Scanner[i].scanner_name_short + ": Scanner died" );

                //We still need to check other possible answers
                continue;
            }

            //If clean, just check next scanner
            if ( buf[0] == '0' ) continue;

            //Virus found?
            if ( buf[0] == '1' )
            {
                //Set answer message (virusname)
                string Temp = buf;
                Temp.erase(0,1);
                if ( Temp == "" ) Temp = "Unknown";

                VirusMsg.push_back( Scanner[i].scanner_name_short + ": " + Temp );

                //Check next descriptor
                continue;
            }
            else //Any other return code must be error
            {
                //Set error message
                string Temp = buf;
                Temp.erase(0,1);
                if ( Temp == "" ) Temp = "Error";

                ErrorMsg.push_back( Scanner[i].scanner_name_short + ": " + Temp );
            }
        }

        //Check next descriptor
    }

    //If virus was found or all scanners returned already, BodyLoop must call GetAnswer()
    if ( answers == totalscanners || VirusMsg.size() ) return true;

    //Continue BodyLoop
    return false;
}
#endif


//Wait and read all remaining scanner answers
int ScannerHandler::GetAnswer()
{
    int ret;
    char buf[100];

#ifdef NOMAND
    //Start scanners
    for ( int i = 0; i < totalscanners; i++ )
    {
        while ((ret = write(Scanner[i].toscanner, (const char*)"s", 1)) < 0 && errno == EINTR);

        if (ret <= 0)
        {
            LogFile::ErrorMessage("Detected dead %s process\n", Scanner[i].scanner_name.c_str());
            for ( int ii = 0; ii < totalscanners; ii++ )
            {
                kill(Scanner[ii].scanner_pid, SIGKILL);
            }
      
            ErrorMsg.push_back( "Detected dead scanner" );
            return 3;
        }
    }
#endif

    while ( answers < totalscanners )
    {
        //Set descriptors that are left
        readfds = scannerfds;

        //Reset timeout
        ScannersTimeout.tv_sec = ScannerTimeout;
        ScannersTimeout.tv_usec = 0;

        //Wait for some scanner to return
        ret = select_eintr(top_fd+1, &readfds, NULL, NULL, &ScannersTimeout);

        //If some scanner has timed out, kill them all
        if ( ret == 0 )
        {
            LogFile::ErrorMessage("Error: Some scanner has timed out! Killing..\n");

            for ( int i = 0; i < totalscanners; i++ )
            {
                kill(Scanner[i].scanner_pid, SIGKILL);
            }

            ErrorMsg.push_back( "Scanner timeout" );
            return 3;
        }

        //Check all descriptors for answer
        for ( int i = 0; i < totalscanners; i++ )
        {
            //Check if this scanner has answer
            if ( FD_ISSET(Scanner[i].fromscanner,&readfds) )
            {
                //We have one answer more!
                ++answers;

                //Remove scanner from list of checked fds
                FD_CLR(Scanner[i].fromscanner,&scannerfds);

                //Lets be safe
                memset(&buf, 0, sizeof(buf));

                //Read scanner answer
                while ((ret = read(Scanner[i].fromscanner, buf, 100)) < 0 && errno == EINTR);

                if (ret <= 0) //Pipe was closed - or some bad error
                {
                    LogFile::ErrorMessage("Detected dead %s process\n", Scanner[i].scanner_name.c_str());

                    ErrorMsg.push_back( Scanner[i].scanner_name_short + ": Scanner died" );

                    //We still need to check other possible answers
                    continue;
                }

                //If clean, just check next scanner
                if ( buf[0] == '0' ) continue;

                //Virus found?
                if ( buf[0] == '1' )
                {
                    //Set answer message (virusname)
                    string Temp = buf;
                    Temp.erase(0,1);
                    if ( Temp == "" ) Temp = "Unknown";

                    VirusMsg.push_back( Scanner[i].scanner_name_short + ": " + Temp );

                    //Check next descriptor
                    continue;
                }
                else //Any other return code must be error
                {
                    //Set error message
                    string Temp = buf;
                    Temp.erase(0,1);
                    if ( Temp == "" ) Temp = "Error";

                    ErrorMsg.push_back( Scanner[i].scanner_name_short + ": " + Temp );
                }
            }

            //Check next descriptor
        }
    }

    //Virus found?
    if ( VirusMsg.size() ) return 1;

    //Return error only if all scanners had one and we want errors
    if ( (ErrorMsg.size() == (unsigned int)totalscanners) && Params::GetConfigBool("FAILSCANERROR") )
    {
        return 2;
    }

    //It's clean.. hopefully
    return 0;
}


//Return scanner answer message
string ScannerHandler::GetAnswerMessage()
{
    string AnswerMsg = "";

    if ( VirusMsg.size() )
    {
        for ( unsigned int i = 0; i < VirusMsg.size(); ++i )
        {
            AnswerMsg += ", " + VirusMsg[i];
        }

        AnswerMsg.erase(0,2);
    }
    else if ( ErrorMsg.size() )
    {
        for ( unsigned int i = 0; i < ErrorMsg.size(); ++i )
        {
            AnswerMsg += ", " + ErrorMsg[i];
        }

        AnswerMsg.erase(0,2);
    }

    return AnswerMsg;
}


//Initialize tempfile
bool ScannerHandler::InitTempFile()
{
    TempFileLength = 0;

    memset(&TempFileName, 0, sizeof(TempFileName));
    strncpy(TempFileName, Params::GetConfigString("SCANTEMPFILE").c_str(), MAXSCANTEMPFILELENGTH);

    if ((fd_tempfile = mkstemp(TempFileName)) < 0)
    {
        LogFile::ErrorMessage("Invalid Scannerfile: %s Error: %s\n", TempFileName, strerror(errno));
        return false;
    }

#ifndef NOMAND
    while (write(fd_tempfile, " ", 1) < 0)
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("Could not write to Scannerfile: %s\n", TempFileName );
        return false;
    }
#endif

#ifndef NOMAND
    while (fchmod(fd_tempfile, S_IRUSR|S_IWUSR|S_IRGRP|S_ISGID) < 0)
#else
    while (fchmod(fd_tempfile, S_IRUSR|S_IWUSR|S_IRGRP) < 0)
#endif
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("InitTempFile fchmod() failed: %s\n", strerror(errno));
        return false;
    }

#ifndef NOMAND
    struct flock lock;

    lock.l_type   = F_WRLCK;
    lock.l_start  = 0;                            // Byte-Offset
    lock.l_whence = SEEK_SET;                     // SEEK_SET, SEEK_CUR oder SEEK_END
    lock.l_len    = MAXFILELOCKSIZE;              // number of bytes; 0 = EOF

    while (fcntl(fd_tempfile, F_SETLK, &lock) < 0)
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("Could not lock Scannerfile: %s\n", TempFileName);
        return false;
    }
#endif

    if (lseek(fd_tempfile, 0, SEEK_SET) < 0)
    {
        LogFile::ErrorMessage("Could not lseek Scannerfile: %s\n", TempFileName);
        return false;
    }

    return true;
}


#ifndef NOMAND
//Fully unlock tempfile
bool ScannerHandler::UnlockTempFile()
{
    struct flock lock;

    lock.l_type   = F_UNLCK;
    lock.l_start  = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len    = 0;

    while (fcntl(fd_tempfile, F_SETLK, &lock) < 0)
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("Could not unlock Scannerfile: %s\n", strerror(errno));
        exit(1);
    }

    return true;
}
#endif


//Delete tempfile
bool ScannerHandler::DeleteTempFile()
{
    if (fd_tempfile > -1) while (close(fd_tempfile) < 0)
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("Could not close() Scannerfile: %s\n", strerror(errno));
        exit(1);
    }
    fd_tempfile = -1;

    while (unlink(TempFileName) < 0)
    {
        //File already deleted
        if (errno == ENOENT) break;
        //Retry if signal received or file busy
        if (errno == EINTR || errno == EBUSY) continue;

        LogFile::ErrorMessage("Could not delete Scannerfile: %s\n", strerror(errno));
        exit(1);
    }

    return true;
}


//Reinitialize tempfile
bool ScannerHandler::ReinitTempFile()
{
    if (lseek(fd_tempfile, 0, SEEK_SET) < 0)
    {
        LogFile::ErrorMessage("Could not lseek Scannerfile: %s\n", strerror(errno));
        exit(1);
    }

    while (ftruncate(fd_tempfile, 0) < 0)
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("Could not truncate file: %s\n", strerror(errno));
        exit(1);
    }

#ifndef NOMAND
    while (write(fd_tempfile, " ", 1) < 0)
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("Could not write file: %s\n", strerror(errno));
        exit(1);
    }
#endif

#ifndef NOMAND
    while (fchmod(fd_tempfile, S_IRUSR|S_IWUSR|S_IRGRP|S_ISGID) < 0)
#else
    while (fchmod(fd_tempfile, S_IRUSR|S_IWUSR|S_IRGRP) < 0)
#endif
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("Could not fchmod() Scannerfile: %s\n", strerror(errno));
        exit(1);
    }

    TempFileLength = 0;

#ifndef NOMAND
    struct flock lock;

    lock.l_type   = F_WRLCK;
    lock.l_start  = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len    = MAXFILELOCKSIZE;

    while (fcntl(fd_tempfile, F_SETLK, &lock) < 0)
    {
        if (errno == EINTR) continue;

        //Some scanner still has tempfile opened
        if (errno == EAGAIN)
        {
            sleep(1);
            continue;
        }

        LogFile::ErrorMessage("Could not lock Scannerfile: %s\n", strerror(errno));
        exit(1);
    }
#endif

    if (lseek(fd_tempfile, 0, SEEK_SET) < 0)
    {
        LogFile::ErrorMessage("Could not lseek Scannerfile: %s\n", strerror(errno));
        exit(1);
    }

    return true;
}


//Set tempfile size
bool ScannerHandler::SetTempFileSize( long long ContentLengthT )
{
    if (lseek(fd_tempfile, (off_t)ContentLengthT-1, SEEK_SET) < 0)
    {
        LogFile::ErrorMessage("Could not lseek Scannerfile: %s\n", strerror(errno));
        return false;
    }

    while (write(fd_tempfile, "1", 1) < 0)
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("Could not write to Scannerfile: %s\n", strerror(errno));
        return false;
    }

    if (lseek(fd_tempfile, 0, SEEK_SET) < 0)
    {
        LogFile::ErrorMessage("Could not lseek Scannerfile: %s\n", strerror(errno));
        return false;
    }

    return true;
}


//Truncate tempfile to size
bool ScannerHandler::TruncateTempFile( long long ContentLengthT )
{
    if (lseek(fd_tempfile, 0, SEEK_SET) < 0)
    {
        LogFile::ErrorMessage("Could not lseek Scannerfile: %s\n", strerror(errno));
        return false;
    }

    while (ftruncate(fd_tempfile, (off_t)ContentLengthT) < 0)
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("Could not truncate Scannerfile: %s\n", strerror(errno));
        exit(1);
    }

    return true;
}


//Write data to tempfile
bool ScannerHandler::ExpandTempFile( string &dataT, bool unlockT )
{
    int total_written = 0;
    int len = dataT.length();
    int ret;

    TempFileLength += len;

    //Handle partial write if interrupted by signal!
    while (total_written < len)
    {
        while ((ret = write(fd_tempfile, dataT.substr(total_written).c_str(), len - total_written)) < 0)
        {
            if (errno == EINTR) continue;

            LogFile::ErrorMessage("Could not expand tempfile: %s %s\n", TempFileName, strerror(errno));
            return false;
        }

        total_written += ret;
    }

#ifndef NOMAND
    //Should we unlock the written part?
    if (unlockT == true)
    {
        struct flock lock;

        lock.l_type   = F_UNLCK;
        lock.l_start  = 0;
        lock.l_whence = SEEK_SET;
        lock.l_len    = TempFileLength;

        while (fcntl(fd_tempfile, F_SETLK, &lock) < 0)
        {
            if (errno == EINTR) continue;

            LogFile::ErrorMessage("Could not unlock file: %s\n", TempFileName);
            return false;
        }
    }
#endif

    return true;
}

#ifndef NOMAND
bool ScannerHandler::ExpandTempFileRange( string &dataT, long long offset )
{
    struct flock lock;
    int total_written = 0;
    int len = dataT.length();
    int ret;
    //off_t origpos;

    //if ((origpos = lseek(fd_tempfile, 0, SEEK_CUR)) < 0) return false;

    if (lseek(fd_tempfile, offset, SEEK_SET) < 0) return false;

    //Handle partial write if interrupted by signal!
    while (total_written < len)
    {
        while ((ret = write(fd_tempfile, dataT.substr(total_written).c_str(), len - total_written)) < 0)
        {
            if (errno == EINTR) continue;

            LogFile::ErrorMessage("Could not expand tempfile: %s %s\n", TempFileName, strerror(errno));
            return false;
        }

        total_written += ret;
    }

    //if (lseek(fd_tempfile, origpos, SEEK_SET) < 0) return false;
    if (lseek(fd_tempfile, 0, SEEK_SET) < 0) return false;

    lock.l_type   = F_UNLCK;
    lock.l_start  = offset;             // byte-offset
    lock.l_whence = SEEK_SET;
    lock.l_len    = len;                // number of bytes; 0 = EOF

    //partly unlock
    if (fcntl(fd_tempfile, F_SETLK, &lock) < 0)
    {
        LogFile::ErrorMessage("Could not unlock file: %s\n", TempFileName);
        return false;
    }

    return true;
}
#endif

//Constructor
ScannerHandler::ScannerHandler()
{
    //Timeout for scanners
    if ( Params::GetConfigInt("SCANNERTIMEOUT") > 0 )
    {
        ScannerTimeout = 60 * Params::GetConfigInt("SCANNERTIMEOUT");
    }
    else
    {
        //10 minutes as failsafe
        ScannerTimeout = 600;
    }
}

//Destructor
ScannerHandler::~ScannerHandler()
{
}
