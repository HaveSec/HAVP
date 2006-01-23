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



#include "default.h"
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

	int ret=0;
	unsigned int no=0;

	cl_free(root);
	root = NULL;

	if ((ret = cl_loaddbdir(cl_retdbdir(), &root, &no)))
	{
	LogFile::ErrorMessage ("Database reload error: %s\n", cl_perror(ret));
	return false;
	}
	if ((ret = cl_build(root)))
	{
	LogFile::ErrorMessage ("Database reload initialization error: %s\n", cl_perror(ret));
	cl_free(root);
	return false;
	}

	LogFile::ErrorMessage ("Database reloaded with %d signatures\n", no);

	cl_statfree(&dbstat);
	memset(&dbstat, 0, sizeof(struct cl_stat));
	cl_statinidir(cl_retdbdir(), &dbstat);

/*
//CH 
       cl_statfree(&dbstat);

        LogFile::ErrorMessage ("Reload Database\n" );
        if ( InitDatabase() == false)
        {
            LogFile::ErrorMessage ("Reload Database - failed\n" );
            return false;
        }
*/
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
        close(fd);
        return 1;
    }

    //Wait till file is set up for scanning
    read(fd, Ready, 1);
    lseek(fd, 0, SEEK_SET);

    if((ret = cl_scandesc(fd, &virname, &size, root, &limits, SCANOPTS)) == CL_VIRUS)
    {

        LogFile::ErrorMessage ("Virus %s in file %s detected!\n", virname, FileName );

        ScannerAnswer=virname;
        close(fd);
        return 1;
    }
    else
    {
        if(ret != CL_CLEAN)
        {
            LogFile::ErrorMessage ("Error Virus scanner: %s %s\n", FileName, cl_perror(ret) );
            ScannerAnswer= cl_perror(ret);
            close(fd);
            return 2;
        }
    }

    close(fd);
    ScannerAnswer="Clean";
    return 0;
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
    int ret;
    char p_read[2];
    memset(&p_read, 0, sizeof(p_read));

    UnlockFile();

    //Wait till scanner finishes with the file
    while ((ret = read(commin[0], &p_read, 1)) < 0)
    {
    	if (errno == EINTR) continue;
    	if (errno != EPIPE) LogFile::ErrorMessage("cl1 read to pipe failed: %s\n", strerror(errno));

    	DeleteFile();
    	exit(0);
    }

    //Truncate and reuse existing tempfile
    if (ReinitFile() == false)
    {
    	LogFile::ErrorMessage("ReinitFile() failed\n");
    }

    //Virus found ? 0=No ; 1=Yes; 2=Scanfail
    return (int)atoi(p_read);
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

