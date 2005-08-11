/***************************************************************************
                          havp.cpp  -  description
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "logfile.h"
#include "default.h"
#include "helper.h"
#include "sockethandler.h"
#include "genericscanner.h"
#include "clamlibscanner.h"
#include "proxyhandler.h"
#include "filehandler.h"

#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <time.h>
//#include <unistd.h>

GenericScanner *VirusScanner;
bool rereaddatabase;
int startchild;
int Instances = 0;
time_t LastRefresh = time(NULL);

int main(int argc, char *argv[])
{

    rereaddatabase = false;
    startchild = 0;

    InstallSignal();

    SocketHandler ProxyServer;
    ProxyHandler Proxy;
    VirusScanner = new (ClamLibScanner);

    if ( ChangeUserAndGroup( ) == false)
        exit (-1);

    if (LogFile::InitLogFiles( ACCESSLOG, ERRORLOG ) == false)
    {
        cout << "Could not create logfiles" << endl;
        exit (-1);
    }

    #ifdef  DISPLAYINITIALMESSAGES
    cout << "Starting Havp Version:" << VERSION << endl;
    #endif

    LogFile::ErrorMessage("Starting Havp Version: %s\n", VERSION);
    #ifdef USER
    LogFile::ErrorMessage ("Change to User %s\n", USER);
    #endif
    #ifdef GROUP
    LogFile::ErrorMessage ("Change to Group %s\n", GROUP);
    #endif

    #if defined (PARENTPROXY) && defined (PARENTPORT)
    LogFile::ErrorMessage("Use parent proxy: %s %d\n", PARENTPROXY, PARENTPORT );
    #endif

    #ifdef TRANSPARENT
    LogFile::ErrorMessage("Use transparent proxy mode\n");
    #endif

    if( HardLockTest ( )!= 1)
    {
        exit (-1);
    }

    if( ProxyServer.CreateServer( PORT, BIND_ADDRESS ) == false)
    {
        cout << "Could not create Server" << endl;
        LogFile::ErrorMessage("Could not create Server\n");
        exit (-1);
    }

    if ( VirusScanner->InitDatabase( ) == false )
    {
        cout << "Could not init scanner database" << endl;
        LogFile::ErrorMessage("Could init scanner database\n");
        exit (-1);
    }

    #ifdef DAEMON
    MakeDeamon();
    #endif

//PSEstart
    //PSE: parent pid of all processes started from now on
    //PSE: may be used later to kill the daemon
    pid_t pid;
    pid=getpid();
    setpgrp();  //PSE: for cases daemon is not started
    LogFile::ErrorMessage ("Process ID: %d\n", pid);

    //create a unique message queue for all children and grandchildren

#ifdef QUEUE
    int qid;
    qid = msgget(IPC_PRIVATE, (IPC_CREAT | 00600) );
    if ( qid < 0) {
	LogFile::ErrorMessage ("Cannot create a message queue! Error: %s\n", strerror(errno));
	if(errno == ENOSPC) {
		LogFile::ErrorMessage ("System-wide variable MSGMNI too small. Increase this value!");
	}
    }
    VirusScanner->msgqid = qid;
    LogFile::ErrorMessage ("Message Queue ID: %d\n", qid);
#endif

//PSEend

    #ifdef SERVERNUMBER
    //PSE: pid_t pid;
    //Start Server
    for( int i = 0; i < SERVERNUMBER; i++ )
    {
        pid=fork();
        Instances++;

        if (pid == 0)
        {
            //Child
            VirusScanner->PrepareScanning ( &ProxyServer );
//PSEstart
//	    VirusScanner->FreeDatabase();
//PSEend
            Proxy.Proxy ( &ProxyServer, VirusScanner );
            exit (1);
        }
    }
    #endif

    while(1)
    {

        //Signal Refresh
        if(rereaddatabase) {
		      rereaddatabase = false;
		      VirusScanner->ReloadDatabase();
    		  LogFile::ErrorMessage ("Database reread by signal\n");
	      }

        //Time Refresh
        if ( time(NULL) > (LastRefresh + DBRELOAD*60) ){
          LastRefresh = time(NULL);
		      rereaddatabase = false;
		      VirusScanner->ReloadDatabase();
    		  LogFile::ErrorMessage ("Database reread by time\n");
        }

        #ifdef SERVERNUMBER

        int status;
        if( (pid = waitpid(-1,&status,WNOHANG)) != 0 )
        {
          Instances--;
          //LogFile::ErrorMessage ("PID %d\n", pid);
        }

	if ((startchild) || (Instances < SERVERNUMBER)){
          //LogFile::ErrorMessage ("Instances %d - startchild %d - Number %d\n", Instances, startchild, SERVERNUMBER);

        	pid=fork();
          Instances++;
        	if (pid < 0)
          {
           LogFile::ErrorMessage ("Could not fork child");
           Instances--;
        	} else if (pid == 0) {
            //Child
            	VirusScanner->PrepareScanning ( &ProxyServer );
//PSEstart
//	    VirusScanner->FreeDatabase();
//PSEend
            	Proxy.Proxy ( &ProxyServer, VirusScanner );
            	exit (1);
        	} else {
		      startchild--;
		      }
	}

 //LogFile::ErrorMessage ("Instances %d - startchild %d\n", Instances, startchild);

 if(Instances >= SERVERNUMBER)
 {
	pause();
 }

        #else
        VirusScanner->PrepareScanning ( &ProxyServer );
//PSEstart
//	VirusScanner->FreeDatabase();
//PSEend
        Proxy.Proxy ( &ProxyServer, VirusScanner );
        #endif
    }
    return 0;
}
