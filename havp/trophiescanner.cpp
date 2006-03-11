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


#include "default.h"
#include "trophiescanner.h"


char TrophieScanner::VIR_NAME[512];

int TrophieScanner::trophie_scanfile(char *scan_file)
{

	int vs_ret = VSVirusScanFileWithoutFNFilter(vs_addr, scan_file, -1);
	
	/* Lame. Hopefully just a temporary thing */
	/* Returned for .bz2 archives, and some MPEG files - not sure why it's -89, but we're not missing viruses */
	if (vs_ret == -89)
		vs_ret = 0;
	
	return vs_ret;
}

int TrophieScanner::vs_callback(char *a, struct callback_type *b, int c, char *d)
{
	/* Only c == 1 needs to be processed = no idea what for 2nd run is used for (and don't want to know) */

	if ( (c == 1) && (b->flag_infected > 0) )
	{
		char *virus_name = (char *)(b->vname+8);

		strncpy(VIR_NAME, virus_name, sizeof(VIR_NAME)-1);

	}

	return(0);
}

//Init Trophie scanner engine
bool TrophieScanner::InitDatabase()
{
	int vs_ret;
	int vs_ptr = 0;

	vs_addr = 0;

	memset(&pattern_info_ex, 0, sizeof(pattern_info_ex));
	memset(&trophie_vs, 0, sizeof(trophie_vs_type));

	if ((vs_ret = VSInit(getpid(), "VSCAN", -1, &vs_addr)) != 0)
	{
		LogFile::ErrorMessage("Trophie VSInit() failed: %d\n", vs_ret);
		return false;
	}
	if ((vs_ret = VSReadVirusPattern(vs_addr, -1, 0, (int *) &vs_ptr)) != 0)
	{
		LogFile::ErrorMessage("Trophie VSReadVirusPattern() failed: %d\n", vs_ret);
		return false;
	}

	trophie_vs.handle_addr = vs_addr;
	trophie_vs.version_string[0] = 0;

	if ((vs_ret = VSGetVSCInfo(&trophie_vs)) != 0)
	{
		LogFile::ErrorMessage("Trophie VSGetVSCInfo() failed: %d\n", vs_ret);
		return false;
	}

	/* Set the callback function */
	if ((vs_ret = VSSetProcessFileCallBackFunc(vs_addr, &TrophieScanner::vs_callback)) != 0)
	{
		LogFile::ErrorMessage("Trophie VSSetProcessFileCallBackFunc() failed: %d\n", vs_ret);
		return false;
	}

	if ((vs_ret = VSGetVirusPatternInfoEx(vs_ptr, (int *) &pattern_info_ex)) != 0)
	{
		LogFile::ErrorMessage("Trophie VSGetVirusPatternInfoEx() failed: %d\n", vs_ret);
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
		vs_ret = VSGetDetectableVirusNumber(vs_addr);

		LogFile::ErrorMessage("Loaded pattern version %d.%.3d.%.2d with %d signatures (VSAPI %s)\n",
			major, number, version, vs_ret, trophie_vs.version_string);
	}

	//Here we will set some params on our own
	if (VS_PROCESS_ALL_FILES_IN_ARCHIVE) VSSetProcessAllFileInArcFlag(vs_addr, 1);
	if (VS_PROCESS_ALL_FILES) VSSetProcessAllFileFlag(vs_addr, 1);

	return true;
}


//Reload scanner engine
bool TrophieScanner::ReloadDatabase()
{
	int vs_ret;

	if ((vs_ret = VSQuit(vs_addr)) != 0)
	{
		LogFile::ErrorMessage("Trophie VSQuit() failed: %d\n", vs_ret);
		return false;
	}

	if (InitDatabase() == false)
	{
		LogFile::ErrorMessage("Trophie database reload failed\n");
		return false;
	}

	return true;
}


//Start scan
int TrophieScanner::Scanning()
{
	int ret, fd;
	char Ready[2];
	ScannerAnswer = "";

	if ((fd = open(FileName, O_RDONLY)) < 0)
	{
		LogFile::ErrorMessage("Could not open file to scan: %s\n", FileName);
		ScannerAnswer = "Could not open file to scan";
		close(fd);
		return 2;
	}

	//Wait till file is set up for scanning
	while (read(fd, Ready, 1) < 0 && errno == EINTR);
	close(fd);

	ret = trophie_scanfile(FileName);

	if (ret)
	{
		ScannerAnswer = VIR_NAME;
		return 1;
	}

	ScannerAnswer = "Clean";
	return 0;
}

void TrophieScanner::FreeDatabase()
{
	VSQuit(vs_addr);
}

//Constructor
TrophieScanner::TrophieScanner()
{
	cur_patt = 0;
}


//Destructor
TrophieScanner::~TrophieScanner()
{
}
