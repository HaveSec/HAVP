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

//Init Clamav scanner engine
bool ClamLibScanner::InitDatabase()
{
int ret=0;
unsigned int no=0;

root = NULL;

    if((ret = cl_loaddbdir(cl_retdbdir(), &root, &no))) {
       LogFile::ErrorMessage ("Clamav Error: %s\n", cl_perror(ret) );
	     return false;
    }

    LogFile::ErrorMessage ("Loaded %d signatures\n", no );

    //Build engine
    if((ret = cl_build(root))) {
       LogFile::ErrorMessage ("Database initialization error: %s\n", cl_strerror(ret) );
       cl_free(root);
       return false;
    }

    /* set up archive limits */
    memset(&limits, 0, sizeof(struct cl_limits));
    limits.maxfiles = MAXSCANFILES; /* max files */
    limits.maxfilesize = MAXARCHIVFILESIZE * 1048576; /* maximal archived file size == 10 Mb */
    limits.maxreclevel = MAXRECLEVEL; /* maximal recursion level */
    limits.maxratio = MAXRATIO; /* maximal compression ratio */
    limits.archivememlim = ARCHIVEMEMLIM; /* disable memory limit for bzip2 scanner */
    
    cl_statinidir(cl_retdbdir(), &dbstat);

return true;
}


//Reload scanner engine
bool ClamLibScanner::ReloadDatabase()
{

 //reload_database ?
 if(cl_statchkdir(&dbstat) == 1)
 {
      cl_statfree(&dbstat);

    LogFile::ErrorMessage ("Reload Database\n" );
   if ( InitDatabase() == false) {
     LogFile::ErrorMessage ("Reload Database - failed\n" );
     return false; }
 }

return true;
}

//Start scan
int ClamLibScanner::Scanning( )
{
int ret, fd;
unsigned long int size = 0;

ScannerAnswer="";

const char *virname;

   if ( (fd = open(FileName, O_RDONLY)) < 0)
   {
      LogFile::ErrorMessage ("Could not open file to scan: %s\n", FileName );
      pthread_mutex_lock( &scan_mutex );
      ScannerAnswer="Error -1";
      pthread_mutex_unlock( &scan_mutex );
      close(fd);
      return -1;
   }

   
    if((ret = cl_scandesc(fd, &virname, &size, root, &limits, CL_SCAN_STDOPT)) == CL_VIRUS)
     {
      LogFile::ErrorMessage ("Virus %s in file %s detect!\n", virname, FileName );
      pthread_mutex_lock( &scan_mutex );
      ScannerAnswer=virname;
      pthread_mutex_unlock( &scan_mutex );
      close(fd);
      return -2;
    } else {
	   if(ret != CL_CLEAN){
        LogFile::ErrorMessage ("Error Virus scanner: %s %s\n", FileName, cl_perror(ret) );
        pthread_mutex_lock( &scan_mutex );
        ScannerAnswer= "Error -2";
        ErrorAnswer = cl_perror(ret);
        pthread_mutex_unlock( &scan_mutex );
        close(fd);
        return -3;
        }
    }

 close(fd);
      pthread_mutex_lock( &scan_mutex );
      ScannerAnswer="Clean";
      pthread_mutex_unlock( &scan_mutex );

 
return 0;
}


//Init scanning engine - do filelock and so on
bool ClamLibScanner::InitSelfEngine() {

if( OpenAndLockFile() == false) {
  return false;}

return true;
}


bool ClamLibScanner::ScanningComplete() {

UnlockFile();

//Wait till scanning is complete
pthread_join( ScannerThread, NULL);

//Delete scanned file
DeleteFile();


//Virus already found
if (( ReadScannerAnswer() != "Clean" ) && ( ReadScannerAnswer() != "" ) )
{
  return false;
}

return true;
}

//Constructor
ClamLibScanner::ClamLibScanner(){

memset(&dbstat, 0, sizeof(struct cl_stat));
  
}

//Destructor
ClamLibScanner::~ClamLibScanner(){
}
