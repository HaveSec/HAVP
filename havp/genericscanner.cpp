/***************************************************************************
                          genericscanner.cpp  -  description
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

#include "genericscanner.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>

bool GenericScanner::PrepareScanning( SocketHandler *ProxyServerT )
{
    pid_t scannerpid;
    extern bool childrestart;

    if ((scannerpid = fork()) < 0)
    {
        LogFile::ErrorMessage("Could not fork Scanner: %s", strerror(errno));
        return false;            //Parent error
    }
    else if (scannerpid != 0)
    {
        //Parent

        //Scanner forked, close proxy ends that are not needed
        if (close(commin[1]) < 0) LogFile::ErrorMessage("Could not close pipe commin[1]\n");
        if (close(commout[0]) < 0) LogFile::ErrorMessage("Could not close pipe commout[0]\n");

        return true;
    }
    //Child

    //Close unwanted sockets
    ProxyServerT->Close();

    //Close pipe ends not needed
    if (close(commin[0]) < 0) LogFile::ErrorMessage("Could not close pipe commin[0]\n");
    if (close(commout[1]) < 0) LogFile::ErrorMessage("Could not close pipe commout[1]\n");

    int ret;
    char buf[2];

    for(;;)
    {
        //Start scanner and get return code
        ret = Scanning();

        memset(&buf, 0, sizeof(buf));
        sprintf(buf, "%d", ret);

        //Send return code for proxyhandler
        while ((ret = write(commin[1], buf, 1)) < 0)
        {
            if (errno == EINTR) continue;
            break;
        }
        if (ret <= 0) break; //Pipe was closed - or some bad error

        //Finally write ScannerAnswer from scanner
        WriteScannerAnswer();

        //Wait for proxyhandler to finish before we loop again - important
        while ((ret = read(commout[0], buf, 1)) < 0)
        {
            if (errno == EINTR) continue;
            break;
        }
        if (ret <= 0) break; //Pipe was closed - or some bad error

        //Continue scanning?
        if (buf[0] == 'q') break;
    }

    //End process
    DeleteFile();
    exit(1);
}

bool GenericScanner::CreatePipes()
{
    //[0] is for reading, [1] is for writing

    int ret;

    if ((ret = pipe(commin)) < 0)
    {
        LogFile::ErrorMessage("Error creating pipe: %s\n", strerror(ret));
        return false;
    }
    if ((ret = pipe(commout)) < 0)
    {
        LogFile::ErrorMessage("Error creating pipe: %s\n", strerror(ret));
        return false;
    }

    return true;
}

void GenericScanner::WriteScannerAnswer()
{
    char out[100];
    memset(&out, 0, sizeof(out));
    
    ScannerAnswer.copy(out, 99);

    while (write(commin[1], out, 100) < 0)
    {
        if (errno == EINTR) continue;

        DeleteFile();
        exit(0);
    }
}

string GenericScanner::ReadScannerAnswer()
{
    char p_read[100];
    memset(&p_read, 0, sizeof(p_read));

    int ret;

    fd_set readfd;
    FD_ZERO(&readfd);
    FD_SET(commin[0], &readfd);

    while ((ret = select(commin[0]+1, &readfd, NULL, NULL, NULL)) < 0)
    {
        if (errno == EINTR) continue;
        LogFile::ErrorMessage("ReadScannerAnswer select failed: %s\n", strerror(ret));
    }

    if ((ret = read(commin[0], p_read, 100)) < 0)
    {
        LogFile::ErrorMessage("ReadScannerAnswer read failed: %s\n", strerror(errno));

        DeleteFile();
        exit(0);
    }

    string Answer = p_read;

    return Answer;
}

int GenericScanner::CheckScanner(bool blocking)
{
    fd_set readfd;
    FD_ZERO(&readfd);
    FD_SET(commin[0], &readfd);

    int ret;

    if (blocking == false)
    {
        struct timeval Timeout;
        Timeout.tv_sec = 0;
        Timeout.tv_usec = 0;

        //Just return select result, 1 means we have answer waiting
        while ((ret = select(commin[0]+1, &readfd, NULL, NULL, &Timeout)) < 0)
        {
            if (errno == EINTR) continue;

            //Return error
            return 2;
        }

        return ret;
    }

    char p_read[2];
    memset(&p_read, 0, sizeof(p_read));

    //Wait for answer
    while (select(commin[0]+1, &readfd, NULL, NULL, NULL) < 0 && errno == EINTR);

    while ((ret = read(commin[0], p_read, 1)) < 0)
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("CheckScanner read failed: %s\n", strerror(errno));
        return 2;
    }
    if (ret == 0) return 2; //If scanner process died(?), return error

    //Convert scanner return value to int
    ret = atoi(p_read);

    //Sanity check
    if ( (ret < 0) || (ret > 2) )
    {
        LogFile::ErrorMessage("Program error: Invalid return from scanner: %d\n", ret);
        ret = 2;
    }

    return ret;
}


//Constructor
GenericScanner::GenericScanner( )
{
    ScannerAnswer = "";
}


//Destructor
GenericScanner::~GenericScanner( )
{

}
