/***************************************************************************
                          clamlibscanner.cpp  -  description
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

#include "clamlibscanner.h"
#include <sys/types.h>
#include <sys/wait.h>

//Init Clamav scanner engine
bool ClamLibScanner::InitDatabase()
{
    int ret=0;
    unsigned int no=0;

    root = NULL;

    if((ret = cl_loaddbdir(cl_retdbdir(), &root, &no)))
    {
        LogFile::ErrorMessage ("Clamav Error: %s\n", cl_perror(ret) );
        return false;
    }

    LogFile::ErrorMessage ("Loaded %d signatures\n", no );

    //Build engine
    if((ret = cl_build(root)))
    {
        LogFile::ErrorMessage ("Database initialization error: %s\n", cl_strerror(ret) );
        cl_free(root);
        return false;
    }

    /* set up archive limits */
    memset(&limits, 0, sizeof(struct cl_limits));
    limits.maxfiles = MAXSCANFILES;               /* max files */
                                                  /* maximal archived file size == 10 Mb */
    limits.maxfilesize = MAXARCHIVFILESIZE * 1048576;
    limits.maxreclevel = MAXRECLEVEL;             /* maximal recursion level */
    limits.maxratio = MAXRATIO;                   /* maximal compression ratio */
    limits.archivememlim = ARCHIVEMEMLIM;         /* disable memory limit for bzip2 scanner */

    cl_statinidir(cl_retdbdir(), &dbstat);

    return true;
}


//Reload scanner engine
bool ClamLibScanner::ReloadDatabase()
{

    //reload_database ?
   //PSE: cl_statchkdir has more exit-codes than 1 and 0 !!!
   //PSE: Error code now catched by InitDatabase (hopefully)
   //PSE: if(cl_statchkdir(&dbstat) == 1)
    if(cl_statchkdir(&dbstat) != 0)
    {
        cl_statfree(&dbstat);

        LogFile::ErrorMessage ("Reload Database\n" );
        if ( InitDatabase() == false)
        {
            LogFile::ErrorMessage ("Reload Database - failed\n" );
            return false;
        }
    }

    return true;
}


//Start scan
int ClamLibScanner::Scanning( )
{
    int ret, fd;
    unsigned long int size = 0;
    char Ready[2];
    ScannerAnswer="";

    const char *virname;

    if ( (fd = open(FileName, O_RDONLY)) < 0)
    {
        LogFile::ErrorMessage ("Could not open file to scan: %s\n", FileName );
        ScannerAnswer="Could not open file to scan";
//PSEstart
	//PSE: We are child but parent process wants this answer to know!
    	WriteScannerAnswer();
//PSEend
        close(fd);
        exit (2);
    }

    //Wait till file is set up for scanning
    read(fd, Ready, 1);

    if((ret = cl_scandesc(fd, &virname, &size, root, &limits, SCANOPTS)) == CL_VIRUS)
    {

        LogFile::ErrorMessage ("Virus %s in file %s detected!\n", virname, FileName );

        ScannerAnswer=virname;
//PSEstart
	//PSE: We are child but parent process wants this answer to know!
    	WriteScannerAnswer();
//PSEend
        close(fd);
        exit (1);
    }
    else
    {
        if(ret != CL_CLEAN)
        {
            LogFile::ErrorMessage ("Error Virus scanner: %s %s\n", FileName, cl_perror(ret) );
            ScannerAnswer= cl_perror(ret);
//PSEstart
	//PSE: We are child but parent process wants this answer to know!
    	WriteScannerAnswer();
//PSEend
            close(fd);
            exit (2);
        }
    }

    close(fd);
    ScannerAnswer="Clean";
//PSEstart
    //PSE: We are child but parent process wants this answer to know!
    WriteScannerAnswer();
//PSEend

    exit (0);
}


//Init scanning engine - do filelock and so on
bool ClamLibScanner::InitSelfEngine()
{

    if( OpenAndLockFile() == false)
    {
        return false;
    }

    return true;
}


int ClamLibScanner::ScanningComplete()
{

    int status=0;

    UnlockFile();

    //Wait till scanning is complete
    waitpid( ScannerPid, &status, 0);

    //Delete scanned file
    DeleteFile();

    //Virus found ? 0=No ; -1=Yes; -2=Scanfail
    return WEXITSTATUS(status);

}

//PSEstart
bool ClamLibScanner::FreeDatabase()
{
	cl_free(root);
	return true;
}
//PSEend

//Constructor
ClamLibScanner::ClamLibScanner()
{

    memset(&dbstat, 0, sizeof(struct cl_stat));

}


//Destructor
ClamLibScanner::~ClamLibScanner()
{
}
