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

    //Prepare first to use tempfile
    if (InitSelfEngine() == false)
    {
        LogFile::ErrorMessage("InitSelfEngine() failed\n");
        return false;
    }

    if ((scannerpid = fork()) < 0)
    {
        return false;            //Parent error
    }
    else if (scannerpid != 0)
    {
        //Parent
        return true;
    }
    //Child

    //Close unwanted sockets
    ProxyServerT->Close();

    //Close pipe ends not needed
    close(commin[0]);
    close(commout[1]);

    int ret;
    int creqs = 0;
    char buf[2];

    //Loop the same amount as Parent
    while (creqs < 500)
    {
        creqs++;

        //Start scanner and get return code
        ret = Scanning();

        memset(&buf, 0, sizeof(buf));
        sprintf(buf, "%d", ret);

        //Send return code for proxyhandler
        while ((ret = write(commin[1], &buf, 1)) < 0)
        {
            if (errno == EINTR) continue;
            if (errno != EPIPE) LogFile::ErrorMessage("gs3 write to pipe failed: %s\n", strerror(errno));

            DeleteFile();
            exit(0);
        }

        //Finally write ScannerAnswer from scanner
        WriteScannerAnswer();

        //Wait for proxyhandler to finish before we loop again - important
        while ((ret = read(commout[0], &buf, 1)) < 0)
        {
            if (errno == EINTR) continue;
            if (errno != EPIPE) LogFile::ErrorMessage("gs4 read to pipe failed: %s\n", strerror(errno));

            DeleteFile();
            exit(0);
        }
    }

    //Exit now because parent has reached maximum reqs
    DeleteFile();
    exit(0);
}

bool GenericScanner::CreatePipes()
{
    if (pipe(commin) < 0)
    {
        LogFile::ErrorMessage("Error creating pipe\n");
        return false;
    }
    if (pipe(commout) < 0)
    {
        LogFile::ErrorMessage("Error creating pipe\n");
        return false;
    }

    return true;
}

void GenericScanner::WriteScannerAnswer()
{
    while (write(commin[1], ScannerAnswer.substr(0,499).c_str(), 500) < 0)
    {
        if (errno == EINTR) continue;
        if (errno != EPIPE) LogFile::ErrorMessage("gs4 write to pipe failed: %s\n", strerror(errno));

        DeleteFile();
        exit(0);
    }
}

string GenericScanner::ReadScannerAnswer()
{
    char p_read[500];
    string Answer;

    memset(&p_read, 0, sizeof(p_read));

    while (read(commin[0], &p_read, 500) < 0)
    {
        if (errno == EINTR) continue;
        if (errno != EPIPE) LogFile::ErrorMessage("gs5 read to pipe failed: %s\n", strerror(errno));

        DeleteFile();
        exit(0);
    }

    Answer.assign(p_read);
    return Answer;
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
