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

#include "default.h"
#include "scannerfilehandler.h"
#include "logfile.h"
#include "params.h"

#include <sys/stat.h>
#include <sys/types.h>
//#include <unistd.h>
//#include <stdlib.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
//#include <sys/ipc.h>
//#include <sys/msg.h>
#include <signal.h>


extern GenericScanner *VirusScanner;

bool WritePidFile(pid_t pid)
{
    string pidfile=Params::GetConfigString("PIDFILE");
    ofstream pidf(pidfile.c_str(),ios_base::trunc);
    if(!pidf) return false;
    pidf << pid << endl;
    pidf.close();

    return true;
}

static void ChildExited (int SignalNo)
{
	int dummy;
	dummy++;
}
static void RereadAll (int SignalNo)
{
 extern bool rereaddatabase;
 extern bool rereadUrlList;
 rereaddatabase = true;
 rereadUrlList = true;
}
static void RestartChild (int SignalNo)
{
 extern bool childrestart;
 childrestart = true;
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

        //Delete PIDfile
        string pidfile=Params::GetConfigString("PIDFILE");

        if ( unlink ( pidfile.c_str() ) == -1)
        {
            LogFile::ErrorMessage("Can not remove pidfile: %s\n", strerror(errno));
        }
 
	exit(0);
    }
    else
    {
	VirusScanner->DeleteFile();
    }

    exit (1);
}


int InstallSignal()
{
    struct sigaction Signal;

    memset(&Signal, 0, sizeof(Signal));

    Signal.sa_flags = 0;

    Signal.sa_handler = DeleteTempfiles;
    if (sigaction(SIGINT, &Signal, NULL) != 0)
    {
        return -1;
    }
    if (sigaction(SIGTERM, &Signal, NULL) != 0)
    {
        return -1;
    }

    Signal.sa_handler = RereadAll;
    if (sigaction(SIGHUP, &Signal, NULL) != 0)
    {
        return -1;
    }
    //Compatibility for 0.77 and older init-script
    if (sigaction(SIGUSR2, &Signal, NULL) != 0)
    {
        return -1;
    }

    Signal.sa_handler = SIG_IGN;
    if (sigaction(SIGUSR1, &Signal, NULL) != 0)
    {
        return -1;
    }

    Signal.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &Signal, NULL) != 0)
    {
        return -1;
    }

    Signal.sa_handler = ChildExited;
    if (sigaction(SIGCHLD, &Signal, NULL) != 0)
    {
        return -1;
    }

    return 0;
}

int InstallChildSignal()
{
    struct sigaction Signal;

    memset(&Signal, 0, sizeof(Signal));

    Signal.sa_flags = 0;

    Signal.sa_handler = RestartChild;
    if (sigaction(SIGUSR1, &Signal, NULL) != 0)
    {
        return -1;
    }

    return 0;
}

int MakeDaemon()
{
    pid_t daemon;
    if (( daemon = fork() ) < 0)
    {                                             //Parent error
        return -1;
    }
    else if ( daemon != 0)
    {
        exit (0);                                 //Parent exit
    }

    //Child

    setsid();
    chdir("/tmp/");
    umask(0);

    //Close stdin/stdout/stderr
    close(0);
    close(1);
    close(2);

    return 0;

}


int HardLockTest()
{

    pid_t pid;
    int fd;
    int status;
    char tmpread[10];
    int testread;
    ScannerFileHandler testlock;

    if ( testlock.OpenAndLockFile() == false )
    {
      LogFile::ErrorMessage("Could not open hardlock check file: %s Error: %s\n", testlock.GetFileName(), strerror(errno));
      cout << "Could not open testfile for mandatory locking!" << endl;
      string user = Params::GetConfigString("USER");
      string scanpath = Params::GetConfigString("SCANTEMPFILE");
      cout << "Maybe you need to: chown " << user << " " << scanpath.substr(0, scanpath.rfind("/")) << endl;
      cout << "Exiting.." << endl;
      exit (-1);
    }

    if (( pid = fork() ) < 0)
    {
        //Parent error
        cout << "Error forking hardlock test" << endl;
        return (-1);
    }
    else if ( pid != 0)
    {
        //Parent
        while ((pid = wait(&status)) < 0 && errno == EINTR);

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
        LogFile::ErrorMessage("Could not open hardlock check file: %s\n", testlock.GetFileName() );
        cout << "Could not open hardlock testfile" << endl;
        exit(1);
    }

    //set nonblocking
    fcntl(fd,F_SETFL,O_NONBLOCK);

    while ((testread = read(fd, tmpread, 1)) < 0 && errno == EINTR);
    close(fd);

    if ( testread > 0)
    {
        cout << "Filesystem not supporting mandatory locks!" << endl;
        cout << "On Linux, you need to mount filesystem with \"-o mand\"" << endl;
        LogFile::ErrorMessage("Filesystem not supporting hardlock! Mount filesystem with -o mand\n");
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
        cout << "Group does not exist: " << grp << endl;
        cout << "You need to: groupadd " << grp << endl;
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
        cout << "User does not exist: " << usr << endl;
        cout << "You need to: useradd " << usr << endl;
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

