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

    if ( InitSelfEngine() == false)
    {
        return false;
    }

#ifdef QUEUE
    msgqid = msgget(IPC_PRIVATE, (IPC_CREAT|00600) );
#endif

    if (( ScannerPid = fork() ) < 0)
    {
        return false;            //Parent error
    }
    else if ( ScannerPid != 0)
    {
    //Parent
        return true;
    }
    //Child

    //Close unwanted sockets
    ProxyServerT->Close();

    Scanning();

    exit (-3);                    //should never get here!!
    return false;
}

//PSEstart
//PSE: a new function WriteScannerAnswer
//PSE: Use IPC to send the answer from child to parent process

void GenericScanner::WriteScannerAnswer() {

#ifdef QUEUE
	struct msgbuf {
		long mtype;
		char mes[100];
		} msgbuf, *buf;
	msgbuf.mtype=42;  // 42 the answer of all questions!
	ScannerAnswer.copy(msgbuf.mes,100,0);
	msgbuf.mes[ScannerAnswer.length()] = 0;
	buf = &msgbuf;
	if(msgsnd(msgqid,buf,sizeof(msgbuf),IPC_NOWAIT) < 0) {
		LogFile::ErrorMessage ("Cannot send Message! Error: %s\n", strerror(errno));
		//PSE: Ooops! And now? Let somebody else do the work!
	}
#endif
}

//PSE: function modified to get answer from child

string GenericScanner::ReadScannerAnswer (){

	string Answer ="";

#ifdef QUEUE
	struct msgbuf {
		long mtype;
		char mes[100];
		} msgbuf, *buf;
	buf = &msgbuf;
	if(msgrcv(msgqid,buf,sizeof(msgbuf),42L,0) <0) {
   LogFile::ErrorMessage ("Cannot read Message! Error: %s\n", strerror(errno));
	Answer="";
	} else {
	Answer = msgbuf.mes;
	}

#endif
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
