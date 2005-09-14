/***************************************************************************
                          helper.cpp  -  description
                             -------------------
    begin                : Sa M� 5 2005
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

#include "scannerfilehandler.h"
#include "default.h"
#include "params.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <sys/ipc.h>
#include <sys/msg.h>


extern GenericScanner *VirusScanner;

bool WritePidFile(pid_t pid)
{
    string pidfile=Params::GetConfigString("PIDFILE");
    ofstream pidf(pidfile.c_str(),ios_base::trunc);
    if(!pidf) return false;
    pidf << pid ;
    pidf.close();
    return true;
}

static void ChildExited (int SignalNo)
{
	int dummy;
	dummy++;
}
static void RereadDatabase (int SignalNo)
{
 extern bool rereaddatabase;
 rereaddatabase = true;
}

static void RereadURLList (int SignalNo)
{
 extern bool rereadUrlList;
 rereadUrlList = true;
}

static void StartNewChild (int SignalNo)
{
 extern int startchild;
 startchild++;
}
static void DeleteTempfiles (int SignalNo)
{
//PSEstart
    // VirusScanner->DeleteFile();
    // PSE  don't start new processes
    pid_t pid;
    pid_t pgid;
    pid=getpid();
    pgid=getpgid(0);
    //PSE: all processes have same pgid!
    if (pid == pgid)
	{
	//PSE: only parent, no scan-file to delete!!
	killpg(pgid,SIGINT);
#ifdef QUEUE
    //PSE: make message queue table empty!
    int msqid;
    msqid = VirusScanner->msgqid;
    if(msqid != -1) {
    	if(msgctl(msqid,IPC_RMID,NULL) < 0) {
    		LogFile::ErrorMessage ("Can not remove Message Queue: %d Error: %s \n", msqid , strerror(errno));
    	}
    }
#endif
	exit(0);
	} else {
	VirusScanner->DeleteFile();
    }
    exit (1);

}


void
InstallSignal ()
{

    struct sigaction Signal;

    memset (&Signal, 0, sizeof (Signal));

    Signal.sa_handler = DeleteTempfiles;          //function

    if (sigaction (SIGINT, &Signal, NULL) != 0)
    {
        LogFile::ErrorMessage ("Could not install signal handler\n" );
        exit (-1);
    }
    if (sigaction (SIGTERM, &Signal, NULL) != 0)
    {
        LogFile::ErrorMessage ("Could not install signal handler\n" );
        exit (-1);
    }

    Signal.sa_handler = RereadDatabase;          //function
    if (sigaction (SIGHUP, &Signal, NULL) != 0)
    {
        LogFile::ErrorMessage ("Could not install signal handler\n" );
        exit (-1);
    }

    Signal.sa_handler = RereadURLList;          //function
    if (sigaction (SIGUSR2, &Signal, NULL) != 0)
    {
        LogFile::ErrorMessage ("Could not install signal handler\n" );
        exit (-1);
    }

    Signal.sa_handler = StartNewChild;          //function
    if (sigaction (SIGUSR1, &Signal, NULL) != 0)
    {
        LogFile::ErrorMessage ("Could not install signal handler\n" );
        exit (-1);
    }

    Signal.sa_handler = ChildExited;          //function
    if (sigaction (SIGCHLD, &Signal, NULL) != 0)
    {
        LogFile::ErrorMessage ("Could not install signal handler\n" );
        exit (-1);
    }


}


int MakeDeamon()
{
    pid_t daemon;
    if (( daemon = fork() ) < 0)
    {                                             //Parent error
        return (-1);
    }
    else if ( daemon != 0)
    {
        exit (0);                                 //Parent exit
    }

    //Child
    setsid();
    chdir("/tmp/");
    umask(0);
    return 0;

}


int HardLockTest ( )
{

    pid_t pid;
    int fd;
    int status;
    char tmpread[10];
    int testread;
    ScannerFileHandler testlock;

    if ( testlock.OpenAndLockFile() == false )
    {

      LogFile::ErrorMessage ("Could not open hardlock check file: %s Error: %s\n", testlock.GetFileName() , strerror(errno) );

        exit (-1);
    }

    if (( pid = fork() ) < 0)
    {                                             //Parent error
        return (-1);
    }
    else if ( pid != 0)
    {
        //Parent
        pid = wait( &status);

        testlock.DeleteFile();

        if ( WEXITSTATUS(status) == 0)
        {
            exit (-1);
        }

        return 1;
    }
    //Child
    if ( (fd = open(testlock.GetFileName() , O_RDONLY)) < 0)
    {
        LogFile::ErrorMessage ("Could not open hardlock check file: %s\n", testlock.GetFileName() );
        exit (1);
    }

    //set nonblocking
    fcntl(fd,F_SETFL,O_NONBLOCK);

    testread = read (fd, tmpread, 1);
    close (fd);
    if ( testread > 0)
    {
        cout << "File could not be hardlock " << testlock.GetFileName() << endl;
        cout << "Mount filesystem with -o mand" << endl;
        LogFile::ErrorMessage ("File could not be hardlock - mount filesystem with -o mand %s\n", testlock.GetFileName() );
        exit (0);
    }
    exit (1);
}

bool ChangeUserAndGroup(string usr, string grp)
{
    if(grp != "") {
    struct group *group;

    if ((group = getgrnam ( grp.c_str() )) == NULL)
    {
        cout << "unknown group: " << grp << endl;
        return false;
    }

    if ( setgid( group->gr_gid ) < 0 )
    {
        cout << "Could not change Group-ID" << endl;
        return false;
    }
    }
    if(usr != "") {

    struct passwd *user;

    if ((user = getpwnam ( usr.c_str() )) == NULL)
    {
        cout << "unknown user: " << usr << endl;
        return false;
    }

    if ( setuid( user->pw_uid ) < 0 )
    {
        cout << "Could not change User-ID" << endl;
        return false;
    }
    }
    return true;
}
