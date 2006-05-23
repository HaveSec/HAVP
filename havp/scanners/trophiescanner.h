/***************************************************************************
                          trophiescanner.h  -  description
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

#ifndef TROPHIESCANNER_H
#define TROPHIESCANNER_H

#include "../genericscanner.h"

#define TROPHIE_VERSION "1.12"
#define VS_PROCESS_ALL_FILES_IN_ARCHIVE 1
#define VS_PROCESS_ALL_FILES 1

extern "C"
{

/* --- VSAPI --- */

/* For VSInit() */
struct trophie_vs_type {
	int handle_addr;
	int vs_pid; /* PID - getpid() result, which we've given to it */
	char vscan_str[9]; /* holds 'VSCAN___' */
	char version_string[11]; /* version string */
	unsigned short pattern_version; /* pattern version */
	unsigned short unknown_1; /* don't care, and don't want to care */
	unsigned long pattern_number; /* pettern number (how many viruses it detects - I think :) */
};

/* For callbackup function */
struct callback_type {
	int flag_infected; /* set to 1 if file is infected */
	int flag_archive; /* is the file to be checked actually an archive? */
	int so_far_it_was_always_minus_one; /* no idea yet for what this is used */
	char *archive_being_scanned; /* The name of the *archive* (filename) being scanned - will be NULL if we're scanning file (not archive) */
	char this_is_how_windows_source_code_looks_like[156]; /* this is definitelly not right, but we don't really care for data inside :) */
	char *vname; /* This is what we care about - virus name :) */
	char *current_filename; /* Filename being checked  */
};

/* This structure is passed to VSGetVirusPatternInfoEx and will receive the
 * extended pattern info
 */

/* For VSGetVirusPatternInfoEx() */
struct pattern_info_ex_type {
unsigned int unknown_1;
unsigned int unknown_2;
unsigned int unknown_3;
unsigned int info; /* As a decimal number: MNNNVV
                      M:   major number
                      NNN: pattern number
                      VV:  pattern version
                      E.g. 195409 is 1.954.09 */
};

/* trophiescanner.cpp */
extern int VSInit(pid_t, char *, int, int *);
extern int VSReadVirusPattern(int, int, int, int *);
extern int VSGetVirusPatternInfoEx(int, int *);
extern int VSGetVSCInfo(struct trophie_vs_type *);
extern int VSGetCurrentPatternFileVersion(int, int *);
extern int VSGetDetectableVirusNumber(int);
/* int VSSetProcessFileCallBackFunc(int, XXX); */
extern int VSSetProcessFileCallBackFunc(int, int(*)(char *a, struct callback_type *b, int c, char *d));
extern int VSSetProcessAllFileInArcFlag(int, int);
extern int VSSetProcessAllFileFlag(int, int);
extern int VSSetExtractFileCountLimit(int, int);
extern int VSSetExtractFileRatioLimit(int, int);
extern int VSSetExtractFileSizeLimit(int, int);
extern int VSSetExtractPath(int, const char *);
extern int VSSetTempPath(int, const char*);
extern int VSQuit(int);

/* trophie_scanfile */
extern int VSVirusScanFileWithoutFNFilter(int, char *, int);

};

class TrophieScanner : public GenericScanner {

private:

string ScannerAnswer;
char Ready[2];

struct trophie_vs_type trophie_vs;
struct pattern_info_ex_type pattern_info_ex;

int trophie_scanfile( char *scan_file );

static int vs_callback( char *a, struct callback_type *b, int c, char *d );
static char VIR_NAME[512];

int vs_addr;
unsigned int cur_patt;

public:

bool InitDatabase();
bool ReloadDatabase();
void FreeDatabase();
string Scan( const char *FileName );

TrophieScanner();
~TrophieScanner();

};

#endif
