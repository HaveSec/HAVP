/***************************************************************************
                          helper.cpp  -  description
                             -------------------
    begin                : Sa Mär 5 2005
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

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

 int MakeDeamon()
{
 pid_t deamon;
 if (( deamon = fork() ) < 0)
 { return (-1); //Parent error
 } else if ( deamon != 0) {
  exit (0); //Parent exit
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


testlock.OpenAndLockFile();

 if (( pid = fork() ) < 0)
 { return (-1); //Parent error
 } else if ( pid != 0) {
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
      exit (-1);
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
