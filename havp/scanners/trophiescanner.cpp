/***************************************************************************
                          trophiescanner.cpp  -  description
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


/*************************************************
 * Some code taken from Trophie by Vanja Hrustic *
 *      http://www.vanja.com/tools/trophie/      *
 *          Thanks for the engineering!          *
 *************************************************/

#include "trophiescanner.h"


char TrophieScanner::VIR_NAME[512];

int TrophieScanner::trophie_scanfile( char *scan_file )
{
    int ret = VSVirusScanFileWithoutFNFilter(vs_addr, scan_file, -1);
    
    /* Lame. Hopefully just a temporary thing */
    /* Returned for .bz2 archives, and some MPEG files - not sure why it's -89, but we're not missing viruses */
    if (ret == -89) ret = 0;
    
    return ret;
}

int TrophieScanner::vs_callback( char *a, struct callback_type *b, int c, char *d )
{
    /* Only c == 1 needs to be processed = no idea what for 2nd run is used for (and don't want to know) */

    if ( (c == 1) && (b->flag_infected > 0) )
    {
        char *virus_name = (char *)(b->vname+8);
        strncpy(VIR_NAME, virus_name, sizeof(VIR_NAME)-1);
    }

    return 0;
}


bool TrophieScanner::InitDatabase()
{
    int ret;
    int vs_ptr = 0;

    vs_addr = 0;

    memset(&pattern_info_ex, 0, sizeof(pattern_info_ex));
    memset(&trophie_vs, 0, sizeof(trophie_vs_type));

    if ((ret = VSInit(getpid(), "VSCAN", -1, &vs_addr)) != 0)
    {
        LogFile::ErrorMessage("Trophie: VSInit() failed: %d\n", ret);
        return false;
    }

    if ((ret = VSSetExtractPath(vs_addr, Params::GetConfigString("TEMPDIR").c_str())) != 0)
    {
        LogFile::ErrorMessage("Trophie: VSSetExtractPath() failed: %d\n", ret);
        return false;
    }

    if ((ret = VSSetTempPath(vs_addr, Params::GetConfigString("TEMPDIR").c_str())) != 0)
    {
        LogFile::ErrorMessage("Trophie: VSSetTempPath() failed: %d\n", ret);
        return false;
    }

    if ((ret = VSSetExtractFileCountLimit(vs_addr, Params::GetConfigInt("TROPHIEMAXFILES"))) != 0)
    {
        LogFile::ErrorMessage("Trophie: VSSetExtractFileCountLimit() failed: %d\n", ret);
        return false;
    }

    if ( Params::GetConfigInt("TROPHIEMAXFILESIZE") > 0 )
    {
        if ((ret = VSSetExtractFileSizeLimit(vs_addr, 1048576 * Params::GetConfigInt("TROPHIEMAXFILESIZE"))) != 0)
        {
            LogFile::ErrorMessage("Trophie: VSSetExtractFileSizeLimit() failed: %d\n", ret);
            return false;
        }
    }

    if ((ret = VSSetExtractFileRatioLimit(vs_addr, Params::GetConfigInt("TROPHIEMAXRATIO"))) != 0)
    {
        LogFile::ErrorMessage("Trophie: VSSetExtractFileRatioLimit() failed: %d\n", ret);
        return false;
    }

    if ((ret = VSReadVirusPattern(vs_addr, -1, 0, (int *) &vs_ptr)) != 0)
    {
        LogFile::ErrorMessage("Trophie: VSReadVirusPattern() failed: %d\n", ret);
        return false;
    }

    trophie_vs.handle_addr = vs_addr;
    trophie_vs.version_string[0] = 0;

    if ((ret = VSGetVSCInfo(&trophie_vs)) != 0)
    {
        LogFile::ErrorMessage("Trophie: VSGetVSCInfo() failed: %d\n", ret);
        return false;
    }

    /* Set the callback function */
    if ((ret = VSSetProcessFileCallBackFunc(vs_addr, &TrophieScanner::vs_callback)) != 0)
    {
        LogFile::ErrorMessage("Trophie: VSSetProcessFileCallBackFunc() failed: %d\n", ret);
        return false;
    }

    if ((ret = VSGetVirusPatternInfoEx(vs_ptr, (int *) &pattern_info_ex)) != 0)
    {
        LogFile::ErrorMessage("Trophie: VSGetVirusPatternInfoEx() failed: %d\n", ret);
        return false;
    }

    //Only show if it changed
    if (pattern_info_ex.info != cur_patt)
    {
        cur_patt = pattern_info_ex.info;

        //Calculate nicer looking version
        int major = pattern_info_ex.info / 100000;
        int number = pattern_info_ex.info / 100 - major * 1000;
        int version = pattern_info_ex.info - major * 100000 - number * 100;

        //Get signature count
        ret = VSGetDetectableVirusNumber(vs_addr);

        LogFile::ErrorMessage("Trophie: Loaded %d signatures (pattern %d.%.3d.%.2d / engine %s)\n", ret, major, number, version, trophie_vs.version_string);
    }

    //Here we will set some params on our own
    if (VS_PROCESS_ALL_FILES_IN_ARCHIVE) VSSetProcessAllFileInArcFlag(vs_addr, 1);
    if (VS_PROCESS_ALL_FILES) VSSetProcessAllFileFlag(vs_addr, 1);

    return true;
}


bool TrophieScanner::ReloadDatabase()
{
    int ret = VSQuit(vs_addr);

    if ( ret != 0 )
    {
        LogFile::ErrorMessage("Trophie: VSQuit() failed: %d\n", ret);
        return false;
    }

    if ( InitDatabase() == false )
    {
        LogFile::ErrorMessage("Trophie: Database reload failed\n");
        return false;
    }

    return true;
}


string TrophieScanner::Scan( const char *FileName )
{
    int ret = trophie_scanfile( (char *)FileName );

    if ( ret ) //Virus Found
    {
        string Temp = VIR_NAME;
        if ( Temp == "" ) Temp = "Unknown";

        ScannerAnswer = "1" + Temp;
        return ScannerAnswer;
    }

    ScannerAnswer = "0Clean";
    return ScannerAnswer;
}


void TrophieScanner::FreeDatabase()
{
    VSQuit(vs_addr);
}


//Constructor
TrophieScanner::TrophieScanner()
{
    ScannerName = "Trend Micro Library Scanner";
    ScannerNameShort = "Trend";

    cur_patt = 0;

    ScannerAnswer.reserve(100);
}


//Destructor
TrophieScanner::~TrophieScanner()
{
}

