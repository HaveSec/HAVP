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


bool ClamLibScanner::InitDatabase()
{
    unsigned int no = 0;
    int ret;

    root = NULL;

    cl_settempdir(Params::GetConfigString("TEMPDIR").c_str(), 0);

    LogFile::ErrorMessage("ClamAV: Using database directory: %s\n", dbdir);

    if ( (ret = cl_loaddbdir(dbdir, &root, &no)) != 0 )
    {
        LogFile::ErrorMessage("ClamAV: Could not load database: %s\n", cl_strerror(ret));
        return false;
    }

    LogFile::ErrorMessage("ClamAV: Loaded %d signatures\n", no);

    //Build engine
    if ( (ret = cl_build(root)) != 0 )
    {
        LogFile::ErrorMessage("ClamAV: Database initialization error: %s\n", cl_strerror(ret));
        cl_free(root);
        return false;
    }

    memset(&dbstat, 0, sizeof(struct cl_stat));
    cl_statinidir(dbdir, &dbstat);

    return true;
}


bool ClamLibScanner::ReloadDatabase()
{
    int ret = cl_statchkdir(&dbstat);

    if ( ret == 1 )
    {
        unsigned int no = 0;

        cl_free(root);
        root = NULL;

        cl_settempdir(Params::GetConfigString("TEMPDIR").c_str(), 0);

        if ( (ret = cl_loaddbdir(dbdir, &root, &no)) != 0 )
        {
            LogFile::ErrorMessage("ClamAV: Could not reload database: %s\n", cl_strerror(ret));
            return false;
        }

        if ( (ret = cl_build(root)) != 0 )
        {
            LogFile::ErrorMessage("ClamAV: Database initialization error: %s\n", cl_strerror(ret));
            cl_free(root);
            return false;
        }

        LogFile::ErrorMessage("ClamAV: Reloaded %d signatures\n", no);

        cl_statfree(&dbstat);

        memset(&dbstat, 0, sizeof(struct cl_stat));
        cl_statinidir(dbdir, &dbstat);

        return true;
    }
    else if ( ret != 0 )
    {
        LogFile::ErrorMessage("ClamAV: Error on database check: %s\n", cl_strerror(ret));
    }

    return false;
}


string ClamLibScanner::Scan( const char *FileName )
{
    int fd = open(FileName, O_RDONLY);

    if ( fd < 0 )
    {
        LogFile::ErrorMessage("ClamAV: Could not open tempfile: %s\n", strerror(errno));
        ScannerAnswer = "2Could not open file to scan";
        return ScannerAnswer;
    }

    //Wait till file is set up for scanning
    while (read(fd, Ready, 1) < 0 && errno == EINTR);
    lseek(fd, 0, SEEK_SET);

    int ret = cl_scandesc(fd, &virname, NULL, root, &limits, scanopts);
    while (close(fd) < 0 && errno == EINTR);

    //Clean?
    if ( ret == CL_CLEAN )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    //Virus?
    if ( ret == CL_VIRUS )
    {
        ScannerAnswer = "1";
        ScannerAnswer += virname;
        return ScannerAnswer;
    }

    //Error..
    ScannerAnswer = "2";
    ScannerAnswer += cl_strerror(ret);
    return ScannerAnswer;
}


void ClamLibScanner::FreeDatabase()
{
    cl_free(root);
}


//Constructor
ClamLibScanner::ClamLibScanner()
{
    ScannerName = "ClamAV Library Scanner";

    memset(&dbdir, 0, sizeof(dbdir));

    if (Params::GetConfigString("CLAMDBDIR") != "")
    {
        strncpy(dbdir, Params::GetConfigString("CLAMDBDIR").c_str(), 254);
    }
    else
    {
        strncpy(dbdir, cl_retdbdir(), 254);
    }

    //Set scanning options
    scanopts = CL_SCAN_STDOPT;

    if ( Params::GetConfigBool("CLAMBLOCKMAX") )
    {
        scanopts = scanopts | CL_SCAN_BLOCKMAX;
    }
    if ( Params::GetConfigBool("CLAMBLOCKENCRYPTED") )
    {
        scanopts = scanopts | CL_SCAN_BLOCKENCRYPTED;
    }

    //Set up archive limits
    memset(&limits, 0, sizeof(limits));
    limits.maxfiles = Params::GetConfigInt("CLAMMAXFILES");
    limits.maxfilesize = 1048576 * Params::GetConfigInt("CLAMMAXFILESIZE");
    limits.maxreclevel = Params::GetConfigInt("CLAMMAXRECURSION");
    limits.maxratio = Params::GetConfigInt("CLAMMAXRATIO");
    limits.archivememlim = 0;

    ScannerAnswer.reserve(100);
}


//Destructor
ClamLibScanner::~ClamLibScanner()
{
}

