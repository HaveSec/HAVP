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
#include "proxyhandler.h"
#include "filehandler.h"
#include "params.h"
#include "whitelist.h"

#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <time.h>
//#include <unistd.h>

#ifdef USECLAM
#include "clamlibscanner.h"
#endif

#ifdef USEFPROT
#include "f-protscanner.h"
#endif

#ifdef USEKASPERSKY
#include "kasperskyscanner.h"
#endif

#ifdef USETROPHIE
#include "trophiescanner.h"
#endif

GenericScanner *VirusScanner;
URLList Whitelist;
URLList Blacklist;
bool rereaddatabase;
bool rereadUrlList;
int startchild;
int Instances = 0;
time_t LastRefresh = time(NULL);


int main(int argc, char *argv[])
{

    rereaddatabase = false;
    startchild = 0;

    if(Params::SetParams(argc,argv) == false) exit(253);
    InstallSignal();

    SocketHandler ProxyServer;
    ProxyHandler Proxy;

#ifdef USECLAM
    VirusScanner = new (ClamLibScanner);
#endif

#ifdef USEFPROT
    VirusScanner = new (FProtScanner);
#endif

#ifdef USEKASPERSKY
    VirusScanner = new (KasperskyScanner);
#endif

#ifdef USETROPHIE
    VirusScanner = new (TrophieScanner);
#endif

    if(Params::GetConfigBool("DISPLAYINITIALMESSAGES")) {
   	cout << "Starting Havp Version: " << VERSION << endl;
    }

    string accesslog = Params::GetConfigString("ACCESSLOG");
    string errorlog = Params::GetConfigString("ERRORLOG");
    if (LogFile::InitLogFiles( accesslog.c_str(), errorlog.c_str() ) == false)
    {
        cout << "Could not create logfiles" << endl;
        exit (-1);
    }

    LogFile::ErrorMessage("Starting Havp Version: %s\n", VERSION );


    string whitelistfile = Params::GetConfigString("WHITELIST");
    if ( Whitelist.CreateURLList(whitelistfile) == false ) {
      cout << "Could not read whitelist!" << endl;
      exit(-1);
    }

    string blacklistfile = Params::GetConfigString("BLACKLIST");
    if ( Blacklist.CreateURLList(blacklistfile) == false ) {
      cout << "Could not read blacklist!" << endl;
      exit(-1);
    }


    string parentproxy=Params::GetConfigString("PARENTPROXY");
    int parentport=Params::GetConfigInt("PARENTPORT");
    if( parentproxy != "" && parentport != 0 )
    LogFile::ErrorMessage("Use parent proxy: %s %d\n", parentproxy.c_str(), parentport );

    if(Params::GetConfigBool("TRANSPARENT"))
    LogFile::ErrorMessage("Use transparent proxy mode\n");

    if( HardLockTest ( )!= 1)
    {
        exit (-1);
    }
 
    int port=Params::GetConfigInt("PORT");
    string bind_address=Params::GetConfigString("BIND_ADDRESS");
    if( ProxyServer.CreateServer( port, bind_address ) == false)
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

    if(Params::GetConfigBool("DAEMON")) MakeDeamon();
    setpgrp();  //PSE: for cases daemon is not started


    string user=Params::GetConfigString("USER");
    string group=Params::GetConfigString("GROUP");
    if ( ChangeUserAndGroup("", group) == false) exit (-1);
    if ( ChangeUserAndGroup(user,"") == false) exit (-1);

    LogFile::ErrorMessage ("Change to group %s\n", group.c_str());
    LogFile::ErrorMessage ("Change to user %s\n", user.c_str());

    //PSE: parent pid of all processes started from now on
    //PSE: may be used later to kill the daemon
    pid_t pid;
    pid=getpid();
    if(! WritePidFile(pid)) {
      cout << "Can not write to PIDFILE!\n";
      LogFile::ErrorMessage ("Can not write to PIDFILE!\n");
    }
    LogFile::ErrorMessage ("Process ID: %d\n", pid);

   int maxserver=Params::GetConfigInt("MAXSERVERS");


    int servernumber = Params::GetConfigInt("SERVERNUMBER");
    int dbreload=Params::GetConfigInt("DBRELOAD");
    while(1)
    {

        //Signal Refresh
        if(rereaddatabase) {
		  rereaddatabase = false;
		  VirusScanner->ReloadDatabase();
                  LastRefresh = time(NULL);
    		  LogFile::ErrorMessage ("Database reread by signal\n");
	}

        //Time Refresh
        if ( time(NULL) > (LastRefresh + dbreload*60) ){
                  LastRefresh = time(NULL);
		  VirusScanner->ReloadDatabase();
    		  LogFile::ErrorMessage ("Database reread by time\n");
        }

        if(rereadUrlList) {
		  rereadUrlList = false;
		  Whitelist.ReloadURLList(whitelistfile);
                  Blacklist.ReloadURLList(blacklistfile);
    		  LogFile::ErrorMessage ("Whitelist/Blacklist reread\n");
        }

	if(servernumber > 0) {
        int status;
        while( (pid = waitpid(-1,&status,WNOHANG)) > 0 )
        {
          Instances--;
          //LogFile::ErrorMessage ("PID %d\n", pid);
        }

	while ((startchild) || (Instances < servernumber)){
          //LogFile::ErrorMessage ("Instances %d - startchild %d - Number %d\n", Instances, startchild, servernumber);

        	pid=fork();
          	Instances++;
        	if (pid < 0) {
           		LogFile::ErrorMessage ("Could not fork child");
           		Instances--;
                        //Sleep and hope error goes away
                        sleep(10);
        	} else if (pid == 0) {
            //Child

                //Set up pipes for scanner<->proxyhandler communication
                if (VirusScanner->CreatePipes() == false)
                {
                    //Pipes not created? Lets wait if condition clears
                    sleep(10);
                    exit(1);
                }

                VirusScanner->PrepareScanning(&ProxyServer);

                //Scanner forked, close pipe ends that are not needed
                close(VirusScanner->commin[1]);
                close(VirusScanner->commout[0]);

                int reqs = 0;

                // Use child for 500 requests
                while (reqs < 500)
                {
                    reqs++;
            	    Proxy.Proxy ( &ProxyServer, VirusScanner );
                }
            	exit (1);
        	} else {
		      if(startchild) startchild--;
		}
	}

 //LogFile::ErrorMessage ("Instances %d - startchild %d\n", Instances, startchild);

 if(Instances >= servernumber)
 {
        bool hangup = ProxyServer.CheckForData();
	sleep(1);
        if( (hangup == true) && (Instances < maxserver) && (ProxyServer.CheckForData() == true) ) {
         startchild++; 
        }
 }

	} else {
	// PROBABLY NEED TO COPY THE PIPE STUFF HERE..
        //VirusScanner->PrepareScanning ( &ProxyServer );
        //Proxy.Proxy ( &ProxyServer, VirusScanner );
        LogFile::ErrorMessage("Set SERVERNUMBER > 0\n");
        exit(0);
	}
    }
    return 0;
}
