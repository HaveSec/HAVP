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

#include "default.h"
#include "logfile.h"
#include "helper.h"
#include "sockethandler.h"
#include "genericscanner.h"
#include "proxyhandler.h"
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

#ifdef USEAVG
#include "avgscanner.h"
#endif

GenericScanner *VirusScanner;
URLList Whitelist;
URLList Blacklist;
bool rereaddatabase;
bool rereadUrlList;
bool childrestart;
int LL; //LogLevel

int main(int argc, char *argv[])
{

    if (Params::SetParams(argc,argv) == false) exit(253);

    LL = Params::GetConfigInt("LOGLEVEL");

    if (Params::GetConfigBool("DISPLAYINITIALMESSAGES"))
    {
        cout << "Starting Havp Version: " << VERSION << endl;
    }

    //Test that some options are sane
    if (Params::GetConfigInt("SERVERNUMBER") < 1)
    {
        cout << "Invalid Config: SERVERNUMBER needs to be greater than 0" << endl;
        cout << "Exiting.." << endl;
        exit(-1);
    }
    if (Params::GetConfigString("ACCESSLOG").substr(0,1) != "/" || Params::GetConfigString("ERRORLOG").substr(0,1) != "/")
    {
        cout << "Invalid Config: Log paths need to be abolute" << endl;
        cout << "Exiting.." << endl;
        exit(-1);
    }
    if (Params::GetConfigString("SCANTEMPFILE").find("XXXXXX") == string::npos)
    {
        cout << "Invalid Config: SCANTEMPFILE must contain string \"XXXXXX\"" << endl;
        cout << "Exiting.." << endl;
        exit(-1);
    }
    if (Params::GetConfigInt("MAXSERVERS") > 500)
    {
        cout << "Note: MAXSERVERS is unusually high! You are sure you want this?" << endl;
    }

    //Install signal handlers
    if (InstallSignal() < 0)
    {
        cout << "Could not install signal handlers" << endl;
        cout << "Exiting.." << endl;
        exit(-1);
    }

    //Change user/group ID
    if (ChangeUserAndGroup(Params::GetConfigString("USER"), Params::GetConfigString("GROUP")) == false)
    {
        cout << "Exiting.." << endl;
        exit(-1);
    }

    if (LogFile::InitLogFiles(Params::GetConfigString("ACCESSLOG").c_str(), Params::GetConfigString("ERRORLOG").c_str()) == false)
    {
        cout << "Could not open logfiles!" << endl;
        cout << "Invalid permissions? Maybe you need: chown " << Params::GetConfigString("USER") << " " << Params::GetConfigString("ACCESSLOG").substr(0, Params::GetConfigString("ACCESSLOG").rfind("/")) << endl;
        cout << "Exiting.." << endl;
        exit(-1);
    }

    //Test that mandatory locking works
    if (HardLockTest() != 1)
    {
        cout << "Exiting.." << endl;
        exit(-1);
    }

    LogFile::ErrorMessage("Starting Havp Version: %s\n", VERSION);
    LogFile::ErrorMessage("Change to user %s\n", Params::GetConfigString("USER").c_str());
    LogFile::ErrorMessage("Change to group %s\n", Params::GetConfigString("GROUP").c_str());

    string whitelistfile = Params::GetConfigString("WHITELIST");
    if (Whitelist.CreateURLList(whitelistfile) == false)
    {
        cout << "Could not read whitelist!" << endl;
        cout << "Exiting.." << endl;
        exit(-1);
    }

    string blacklistfile = Params::GetConfigString("BLACKLIST");
    if (Blacklist.CreateURLList(blacklistfile) == false)
    {
        cout << "Could not read blacklist!" << endl;
        cout << "Exiting.." << endl;
        exit(-1);
    }

    string parentproxy = Params::GetConfigString("PARENTPROXY");
    int parentport = Params::GetConfigInt("PARENTPORT");

    if (Params::GetConfigString("PARENTPROXY") != "")
    {
        LogFile::ErrorMessage("Use parent proxy: %s %d\n", parentproxy.c_str(), parentport);
    }

    if (Params::GetConfigBool("TRANSPARENT"))
    {
        LogFile::ErrorMessage("Use transparent proxy mode\n");
    }

    SocketHandler ProxyServer;

    if (ProxyServer.CreateServer(Params::GetConfigInt("PORT"), Params::GetConfigString("BIND_ADDRESS")) == false)
    {
        cout << "Could not create Server" << endl;
        LogFile::ErrorMessage("Could not create Server\n");
        cout << "Exiting.." << endl;
        exit(-1);
    }

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
#ifdef USEAVG
    VirusScanner = new (AVGScanner);
#endif

    if (VirusScanner->InitDatabase() == false)
    {
        cout << "Could not init scanner database" << endl;
        LogFile::ErrorMessage("Could not init scanner database\n");
        cout << "Exiting.." << endl;
        exit(-1);
    }

    if (Params::GetConfigBool("DAEMON"))
    {
        if (MakeDaemon() < 0)
        {
            cout << "Could not fork daemon" << endl;
            cout << "Exiting.." << endl;
            exit(-1);
        }
    }

    pid_t pid = getpid();
    if(! WritePidFile(pid))
    {
        LogFile::ErrorMessage("Can not write to PIDFILE!\n");
    }
    LogFile::ErrorMessage("Process ID: %d\n", pid);

    //Start Server
    int maxservers = Params::GetConfigInt("MAXSERVERS");
    int servernumber = Params::GetConfigInt("SERVERNUMBER");
    int dbreload = Params::GetConfigInt("DBRELOAD");

    int Instances = 0;
    int startchild = 0;
    time_t LastRefresh = time(NULL);
    bool restartchilds = false;

    ProxyHandler Proxy;

    //Infinite Server Loop
    for(;;)
    {
        //Signal Refresh
        if(rereaddatabase)
        {
            LastRefresh = time(NULL);
            rereaddatabase = false;

            LogFile::ErrorMessage("Signal HUP received, reloading virus patterns\n");

            if (VirusScanner->ReloadDatabase() == true)
            {
                restartchilds = true;
            }
        }
        //Time Refresh
        else if (time(NULL) > (LastRefresh + dbreload*60))
        {
            LastRefresh = time(NULL);

            if (VirusScanner->ReloadDatabase() == true)
            {
                restartchilds = true;
            }
        }

        if (rereadUrlList)
        {
	    LogFile::ErrorMessage("Signal HUP received, reloading whitelist/blacklist\n");
            rereadUrlList = false;
            Whitelist.ReloadURLList(whitelistfile);
            Blacklist.ReloadURLList(blacklistfile);
            restartchilds = true;
        }

        //Send restart signal to childs if needed
        if (restartchilds)
        {
            restartchilds = false;
            killpg(getpgid(0), SIGUSR1);
        }

        //Number of defined Processes from havp.config
        int status;

        //Clean zombies up
        while (waitpid(-1, &status, WNOHANG) > 0) Instances--;

        while ((startchild > 0) || (Instances < servernumber))
        {
            if ((pid = fork()) < 0) //Fork Error
            {
                //Too many processes or out of memory?
                LogFile::ErrorMessage("Could not fork proxychild: %s\n", strerror(errno));
                    
                //Lets hope the the causing error goes away soon
                sleep(10);
            }
            else if (pid == 0) //Child
            {
                //Install additional handlers for database updates
                if (InstallChildSignal() < 0)
                {
                    LogFile::ErrorMessage("Error installing Child signals\n");
                    sleep(10);
                    exit(1);
                }

                //Create pipes for scanner<->proxy controlling
                if (VirusScanner->CreatePipes() == false)
                {
                    //Pipes not created? Lets wait if condition clears
                    sleep(10);
                    exit(1);
                }

                //Create initial tempfile
                if (VirusScanner->OpenAndLockFile() == false)
                {
                    sleep(10);
                    exit(1);
                }

                //Fork scanner
                if (VirusScanner->PrepareScanning(&ProxyServer) == false)
                {
                    sleep(10);
                    exit(1);
                }

                //Start processing requests
                Proxy.Proxy(&ProxyServer, VirusScanner);

                exit(1);
            }
            else //Parent
            {
                if (startchild > 0) startchild--;
                Instances++;
            }
        }

        //Do we need more proxy-processes?
        if (Instances >= servernumber)
        {
            bool hangup = ProxyServer.CheckForData(0);
            sleep(1);

            if ((hangup == true) && (Instances < maxservers))
            {
                //Did a old process take care or is there still data? Create two if needed
                if (ProxyServer.CheckForData(0))
                {
                    if (LL>0) LogFile::ErrorMessage("All childs busy, spawning new (now: %d) - SERVERNUMBER might be too low\n", Instances+2);
                    startchild += 2;
                }
            }
        }
    }

    return 0;
}
