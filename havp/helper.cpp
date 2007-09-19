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
#include "params.h"
#include "logfile.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <errno.h>
#include <iostream>
#include <fstream>

extern char TempFileName[MAXSCANTEMPFILELENGTH+1];
extern int fd_tempfile;

static void ChildExited( int SignalNo )
{
    //Handle with waitpid() in havp.cpp
}

static void ChildChildExited( int SignalNo )
{
    int status;
    while (waitpid(-1, &status, WNOHANG) > 0);
}

static void RereadAll( int SignalNo )
{
    extern bool rereadall;
    rereadall = true;
}

static void RestartChild( int SignalNo )
{
    extern bool childrestart;
    childrestart = true;
}

static void ExitProcess( int SignalNo )
{
    pid_t pgid = getpgid(0);

    //PSE: all processes have same pgid!
    if (getpid() == pgid)
    {
	//PSE: only parent, no scan-file to delete!!
	killpg(pgid,SIGINT);

	//Delete pidfile
	while (unlink(Params::GetConfigString("PIDFILE").c_str()) < 0 && (errno == EINTR || errno == EBUSY));
    }
    else
    {
        if (fd_tempfile > -1)
        {
            //Delete tempfile
            while (close(fd_tempfile) < 0 && errno == EINTR);
            while (unlink(TempFileName) < 0 && (errno == EINTR || errno == EBUSY));
        }
    }

    //End process
    exit(0);
}


//Install Signal Handlers for different fork levels
int InstallSignal( int level )
{
    struct sigaction Signal;
    memset(&Signal, 0, sizeof(Signal));
    Signal.sa_flags = 0;

    //Level 0 = Main Havp Process
    //Level 1 = ProxyHandler Process
    //Level 2 = Scanner Process
    //Signals are inherited from previous level at forking..

    if ( level == 0 ) //Main Havp Process
    {
        Signal.sa_handler = ExitProcess;
        if (sigaction(SIGINT, &Signal, NULL) != 0) return -1;
        if (sigaction(SIGTERM, &Signal, NULL) != 0) return -1;

        Signal.sa_handler = RereadAll;
        if (sigaction(SIGHUP, &Signal, NULL) != 0) return -1;
        //Compatibility for 0.77 and older init-script
        if (sigaction(SIGUSR2, &Signal, NULL) != 0) return -1;

        Signal.sa_handler = ChildExited;
        if (sigaction(SIGCHLD, &Signal, NULL) != 0) return -1;

        Signal.sa_handler = SIG_IGN;
        if (sigaction(SIGUSR1, &Signal, NULL) != 0) return -1;
        if (sigaction(SIGPIPE, &Signal, NULL) != 0) return -1;
    }
    else if ( level == 1 ) //ProxyHandler Process
    {
        Signal.sa_handler = RestartChild;
        if (sigaction(SIGUSR1, &Signal, NULL) != 0) return -1;

        Signal.sa_handler = ChildChildExited;
        if (sigaction(SIGCHLD, &Signal, NULL) != 0) return -1;

        Signal.sa_handler = SIG_IGN;
        if (sigaction(SIGHUP, &Signal, NULL) != 0) return -1;
        if (sigaction(SIGUSR2, &Signal, NULL) != 0) return -1;
    }
    else if ( level == 2 ) //Scanner Process
    {
        Signal.sa_handler = SIG_IGN;
        if (sigaction(SIGUSR1, &Signal, NULL) != 0) return -1;
    }

    return 0;
}


bool MakeDaemon()
{
    pid_t daemon = fork();

    if ( daemon < 0 )
    {
        return false;
    }
    else if (daemon != 0)
    {
        //Exit Parent
        exit(0);
    }
    //Child

    setsid();
    chdir("/tmp/");
    umask(077);

    //Close stdin/stdout/stderr
    close(0);
    close(1);
    close(2);

    return true;
}


bool HardLockTest()
{
    memset(&TempFileName, 0, sizeof(TempFileName));
    strncpy(TempFileName, Params::GetConfigString("SCANTEMPFILE").c_str(), MAXSCANTEMPFILELENGTH);

    if ((fd_tempfile = mkstemp(TempFileName)) < 0)
    {
        string Error = strerror(errno);
        cout << "Could not open lock testfile " << TempFileName << ": " << Error << endl;
        string user = Params::GetConfigString("USER");
        string scanpath = Params::GetConfigString("SCANTEMPFILE");
        cout << "Maybe you need to: chown " << user << " " << scanpath.substr(0, scanpath.rfind("/")) << endl;
        return false;
    }

#ifndef NOMAND
    while (fchmod(fd_tempfile, S_IRUSR|S_IWUSR|S_IRGRP|S_ISGID) < 0)
#else
    while (fchmod(fd_tempfile, S_IRUSR|S_IWUSR|S_IRGRP) < 0)
#endif
    {
        if (errno == EINTR) continue;

        string Error = strerror(errno);
        cout << "Testfile fchmod() failed: " << Error << endl;
        return false;
    }

    char eicardata[] = "a5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\0";
    eicardata[0] = 'X';

    while (write(fd_tempfile, eicardata, 68) < 0)
    {
        if (errno == EINTR) continue;

        LogFile::ErrorMessage("Could not write to Scannerfile: %s\n", TempFileName );
        return false;
    }

#ifdef NOMAND
    return true;

#else
    struct flock lock;

    lock.l_type   = F_WRLCK;
    lock.l_start  = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len    = MAXFILELOCKSIZE;

    while (fcntl(fd_tempfile, F_SETLK, &lock) < 0)
    {
        if (errno == EINTR) continue;

        string Error = strerror(errno);
        cout << "Testfile fcntl() failed: " << Error << endl;
        return false;
    }

    if (lseek(fd_tempfile, 0, SEEK_SET) < 0)
    {
        string Error = strerror(errno);
        cout << "Testfile lseek() failed: " << Error << endl;
        return false;
    }

    pid_t testpid = fork();

    if (testpid < 0)
    {
        string Error = strerror(errno);
        cout << "Error forking lock test: " << Error << endl;
        return false;
    }
    else if (testpid != 0)
    {
        //Parent
        int status;
        while ((testpid = wait(&status)) < 0 && errno == EINTR);

        if (WEXITSTATUS(status) == 1)
        {
            return false;
        }

        //Descriptor not needed anymore
        while (close(fd_tempfile) < 0 && errno == EINTR);
        fd_tempfile = -1;

        return true;
    }
    //Child

    int fd;

    if ((fd = open(TempFileName, O_RDONLY)) < 0)
    {
        string Error = strerror(errno);
        cout << "Could not open lock testfile " << TempFileName << ": " << Error << endl;
        exit(1);
    }

    //Set nonblocking
    while (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    {
        if (errno == EINTR) continue;

        string Error = strerror(errno);
        cout << "Testfile fcntl() failed: " << Error << endl;
        exit(1);
    }

    int testread;
    char tmpread[2];

    while ((testread = read(fd, tmpread, 1)) < 0 && errno == EINTR);
    while (close(fd) < 0 && errno == EINTR);

    if (testread > 0)
    {
        cout << "Filesystem not supporting mandatory locks!" << endl;
        cout << "On Linux, you need to mount filesystem with \"-o mand\"" << endl;
        exit(1);
    }

    //Success
    exit(0);
#endif
}


bool ChangeUserAndGroup( string usr, string grp )
{
    if ( geteuid() != 0 ) return true;

    if ( usr == "" || grp == "" )
    {
        cout << "You must define User and Group" << endl;
        return false;
    }

    struct passwd *user;
    struct group *my_group;

    if ( (user = getpwnam( usr.c_str() )) == NULL )
    {
        cout << "User does not exist: " << usr << endl;
        cout << "You need to: useradd " << usr << endl;
        return false;
    }

    if ( (my_group = getgrnam( grp.c_str() )) == NULL )
    {
        cout << "Group does not exist: " << grp << endl;
        cout << "You need to: groupadd " << grp << endl;
        return false;
    }

#ifdef HAVE_INITGROUPS
    if ( initgroups( usr.c_str(), user->pw_gid ) )
    {
        cout << "Group initialization failed (initgroups)" << endl;
        return false;
    }
#else
#if HAVE_SETGROUPS
    if ( setgroups(1, &user->pw_gid) )
    {
        cout << "Group initialization failed (setgroups)" << endl;
        return false;
    }
#endif
#endif

    if ( setgid( my_group->gr_gid ) < 0 )
    {
        cout << "Could not change group to: " << grp << endl;
        return false;
    }

    if ( setuid( user->pw_uid ) < 0 )
    {
        cout << "Could not change user to: " << usr << endl;
        return false;
    }

    return true;
}

string GetUser()
{
    struct passwd *user = getpwuid( geteuid() );
    if ( user == NULL ) return "<error>";
    return (string)user->pw_name;
}

string GetGroup()
{
    struct group *my_group = getgrgid( getegid() );
    if ( my_group == NULL ) return "<error>";
    return (string)my_group->gr_name;
}

bool WritePidFile( pid_t havp_pid )
{
    ofstream pidf( Params::GetConfigString("PIDFILE").c_str(), ios_base::trunc );

    if ( !pidf ) return false;

    pidf << havp_pid << endl;

    pidf.close();

    return true;
}

