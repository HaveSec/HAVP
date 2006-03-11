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

    string tempdir = Params::GetConfigString("TEMPDIR");
    cl_settempdir(tempdir.c_str(), 0);

    if((ret = cl_loaddbdir(cl_retdbdir(), &root, &no)))
    {
        LogFile::ErrorMessage("Clamav Error: %s\n", cl_strerror(ret));
        return false;
    }

    LogFile::ErrorMessage("Loaded %d signatures\n", no);

    //Build engine
    if((ret = cl_build(root)))
    {
        LogFile::ErrorMessage("Database initialization error: %s\n", cl_strerror(ret));
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

    memset(&dbstat, 0, sizeof(struct cl_stat));
    cl_statinidir(cl_retdbdir(), &dbstat);

    return true;
}


//Reload scanner engine
//Return true only if database reloaded, thus childs need to be restarted
bool ClamLibScanner::ReloadDatabase()
{
    int ret_cl = cl_statchkdir(&dbstat);

    if (ret_cl == 1)
    {

	int ret=0;
	unsigned int no=0;

	cl_free(root);
	root = NULL;

	string tempdir = Params::GetConfigString("TEMPDIR");
	cl_settempdir(tempdir.c_str(), 0);

	if ((ret = cl_loaddbdir(cl_retdbdir(), &root, &no)))
	{
	LogFile::ErrorMessage("Database reload error: %s\n", cl_strerror(ret));
	return false;
	}
	if ((ret = cl_build(root)))
	{
	LogFile::ErrorMessage("Database reload initialization error: %s\n", cl_strerror(ret));
	cl_free(root);
	return false;
	}

	LogFile::ErrorMessage("Database reloaded with %d signatures\n", no);

	cl_statfree(&dbstat);
	memset(&dbstat, 0, sizeof(struct cl_stat));
	cl_statinidir(cl_retdbdir(), &dbstat);

	return true;
    }
    else if (ret_cl != 0)
    {
    	LogFile::ErrorMessage("Database reload error: %s\n", cl_strerror(ret_cl));
    }

    return false;
}


//Start scan
int ClamLibScanner::Scanning( )
{
    int ret, fd;
    unsigned long int size = 0;
    char Ready[2];
    ScannerAnswer = "";

    const char *virname;

    if ( (fd = open(FileName, O_RDONLY)) < 0)
    {
        LogFile::ErrorMessage("Could not open file to scan: %s\n", FileName);
        ScannerAnswer = "Could not open file to scan";
        close(fd);
        return 2;
    }

    //Wait till file is set up for scanning
    while (read(fd, Ready, 1) < 0 && errno == EINTR);
    lseek(fd, 0, SEEK_SET);

    if((ret = cl_scandesc(fd, &virname, &size, root, &limits, SCANOPTS)) == CL_VIRUS)
    {
        ScannerAnswer = virname;
        close(fd);
        return 1;
    }
    else if (ret != CL_CLEAN)
    {
        ScannerAnswer = cl_strerror(ret);
        close(fd);
        return 2;
    }

    ScannerAnswer = "Clean";
    close(fd);
    return 0;
}

void ClamLibScanner::FreeDatabase()
{
	cl_free(root);
}

//Constructor
ClamLibScanner::ClamLibScanner()
{
}


//Destructor
ClamLibScanner::~ClamLibScanner()
{
}

