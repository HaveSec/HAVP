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

extern int LL;

#include "clamlibscanner.h"


bool ClamLibScanner::InitDatabase()
{
    unsigned int sigs = 0;
    int ret;
    if (LL>2) cl_debug();

#ifdef CL_INIT_DEFAULT
    if ( (ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS )
    {
        printf("ClamAV: cl_init() error: %s\n", cl_strerror(ret));
        return false;
    }
    if ( !(engine = cl_engine_new()) )
    {
        printf("ClamAV: cl_engine_new() failed\n");
        return false;
    }

    // Limits
    if ( (ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, (long long)1048576 * Params::GetConfigInt("CLAMMAXSCANSIZE"))) )
    {
        LogFile::ErrorMessage("ClamAV: set CL_ENGINE_MAX_SCANSIZE failed: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return false;
    }

    if ( (ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, (long long)1048576 * Params::GetConfigInt("CLAMMAXFILESIZE"))) )
    {
        LogFile::ErrorMessage("ClamAV: set CL_ENGINE_MAX_FILESIZE failed: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return false;
    }

    if ( (ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILES, (long long)Params::GetConfigInt("CLAMMAXFILES"))) )
    {
        LogFile::ErrorMessage("ClamAV: set CL_ENGINE_MAX_FILES failed: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return false;
    }

    if ( (ret = cl_engine_set_num(engine, CL_ENGINE_MAX_RECURSION, (long long)Params::GetConfigInt("CLAMMAXRECURSION"))) )
    {
        LogFile::ErrorMessage("ClamAV: set CL_ENGINE_MAX_RECURSION failed: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return false;
    }

    // Tempdir
    if ( (ret = cl_engine_set_str(engine, CL_ENGINE_TMPDIR, Params::GetConfigString("TEMPDIR").c_str())) )
    {
        LogFile::ErrorMessage("ClamAV: set CL_ENGINE_TMPDIR failed: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return false;
    }

#else
    engine = NULL;
    cl_settempdir(Params::GetConfigString("TEMPDIR").c_str(), 0);
#endif

    LogFile::ErrorMessage("ClamAV: Using database directory: %s\n", dbdir);

#ifdef CL_INIT_DEFAULT
    if ( (ret = cl_load(dbdir, engine, &sigs, 0)) != CL_SUCCESS )
#else
    if ( (ret = cl_load(dbdir, &engine, &sigs, 0)) != 0 )
#endif
    {
        LogFile::ErrorMessage("ClamAV: Could not load database: %s\n", cl_strerror(ret));
        return false;
    }

    LogFile::ErrorMessage("ClamAV: Loaded %d signatures (engine %s)\n", sigs, cl_retver());

    //Build engine
#ifdef CL_INIT_DEFAULT
    if ( (ret = cl_engine_compile(engine)) != CL_SUCCESS )
#else
    if ( (ret = cl_build(engine)) != 0 )
#endif
    {
        LogFile::ErrorMessage("ClamAV: Database initialization error: %s\n", cl_strerror(ret));
#ifdef CL_INIT_DEFAULT
        cl_engine_free(engine);
#else
        cl_free(engine);
#endif
        return false;
    }

    memset(&dbstat, 0, sizeof(struct cl_stat));
    cl_statinidir(dbdir, &dbstat);

    return true;
}


int ClamLibScanner::ReloadDatabase()
{
    int ret = cl_statchkdir(&dbstat);

    if ( ret == 1 )
    {
        unsigned int sigs = 0;
        struct cl_settings *settings = NULL;

#ifdef CL_INIT_DEFAULT
        if ( engine )
        {
            settings = cl_engine_settings_copy(engine);
            if ( !settings ) LogFile::ErrorMessage("ClamAV: cl_engine_settings_copy() failed\n");
            cl_engine_free(engine);
        }
        if ( !(engine = cl_engine_new()) )
        {
            printf("ClamAV: cl_engine_new() failed\n");
            return false;
        }
        if ( settings )
        {
            if ( (ret = cl_engine_settings_apply(engine, settings)) != CL_SUCCESS )
            {
                LogFile::ErrorMessage("ClamAV: cl_engine_settings_apply() failed: %s\n", cl_strerror(ret));
            }
            cl_engine_settings_free(settings);
        }
#else
        cl_free(engine);
        engine = NULL;
        cl_settempdir(Params::GetConfigString("TEMPDIR").c_str(), 0);
#endif


#ifdef CL_INIT_DEFAULT
        if ( (ret = cl_load(dbdir, engine, &sigs, 0)) != CL_SUCCESS )
#else
        if ( (ret = cl_load(dbdir, &engine, &sigs, 0)) != 0 )
#endif
        {
            LogFile::ErrorMessage("ClamAV: Could not reload database: %s\n", cl_strerror(ret));
#ifdef CL_INIT_DEFAULT
            cl_engine_free(engine);
#else
            cl_free(engine);
#endif
            return -1;
        }

#ifdef CL_INIT_DEFAULT
        if ( (ret = cl_engine_compile(engine)) != CL_SUCCESS )
#else
        if ( (ret = cl_build(engine)) != 0 )
#endif
        {
            LogFile::ErrorMessage("ClamAV: Database initialization error: %s\n", cl_strerror(ret));
#ifdef CL_INIT_DEFAULT
            cl_engine_free(engine);
#else
            cl_free(engine);
#endif
            return -1;
        }

        LogFile::ErrorMessage("ClamAV: Reloaded %d signatures (engine %s)\n", sigs, cl_retver());

        cl_statfree(&dbstat);

        memset(&dbstat, 0, sizeof(struct cl_stat));
        cl_statinidir(dbdir, &dbstat);

        return 1;
    }
    else if ( ret != 0 )
    {
        LogFile::ErrorMessage("ClamAV: Error on database check: %s\n", cl_strerror(ret));
    }

    return 0;
}


string ClamLibScanner::Scan( const char *FileName )
{
#ifdef CL_INIT_DEFAULT
    int ret = cl_scanfile(FileName, &virname, NULL, engine, scanopts);
#else
    int ret = cl_scanfile(FileName, &virname, NULL, engine, &limits, scanopts);
#endif

    //Clean?
    if ( ret == CL_CLEAN )
    {
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    //Virus?
    if ( ret == CL_VIRUS )
    {
        //Ignore Oversized.XXX errors? ClamAV does not honour BLOCKMAX on Ratio
        if ( (strstr(virname, "Oversized.") != NULL) && (Params::GetConfigBool("CLAMBLOCKMAX") == false) )
        {
            ScannerAnswer = "0Clean";
            return ScannerAnswer;
        }

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
#ifdef CL_INIT_DEFAULT
    int ret = cl_engine_free(engine);
    if ( ret != CL_SUCCESS )
    {
        LogFile::ErrorMessage("ClamAV: cl_engine_free() failed: %s\n", cl_strerror(ret));
    }
#else
    cl_free(engine);
#endif
}


//Constructor
ClamLibScanner::ClamLibScanner()
{
    ScannerName = cl_retver();

    if ( MatchSubstr( ScannerName, "devel", -1 ) )
    {
        ScannerName = "ClamAV Library Scanner (devel)";
    }
    else
    {
        ScannerName = "ClamAV Library Scanner";
    }

    ScannerNameShort = "ClamAV";

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
    if ( Params::GetConfigBool("CLAMBLOCKBROKEN") )
    {
        scanopts = scanopts | CL_SCAN_BLOCKBROKEN;
    }

    //Set up archive limits
#ifndef CL_INIT_DEFAULT
    memset(&limits, 0, sizeof(limits));
    limits.maxfiles = Params::GetConfigInt("CLAMMAXFILES");
    limits.maxfilesize = 1048576 * Params::GetConfigInt("CLAMMAXFILESIZE");
    limits.maxreclevel = Params::GetConfigInt("CLAMMAXRECURSION");
    limits.maxscansize = 1048576 * Params::GetConfigInt("CLAMMAXSCANSIZE");
    limits.archivememlim = 0;
#endif

    ScannerAnswer.reserve(100);
}


//Destructor
ClamLibScanner::~ClamLibScanner()
{
}

