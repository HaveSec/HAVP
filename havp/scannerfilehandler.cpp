/***************************************************************************
                          scannerfilehandler.cpp  -  description
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

#include "scannerfilehandler.h"

//Open and lock file which will be scanned
bool ScannerFileHandler::OpenAndLockFile()
{

    struct flock lock;
    struct stat fstatpuff;

    FileLength = 0;

    lock.l_type   = F_WRLCK;
    lock.l_start  = 0;                            // Byte-Offset
    lock.l_whence = SEEK_SET;                     // SEEK_SET, SEEK_CUR oder SEEK_END
    lock.l_len    = MAXFILELOCKSIZE;              // number of bytes; 0 = EOF

    string scantempfile = Params::GetConfigString("SCANTEMPFILE");
    strncpy(FileName, scantempfile.c_str(), MAXSCANTEMPFILELENGTH);

    if ((fd_scan = mkstemp(FileName)) < 0)
    {
        LogFile::ErrorMessage("Invalid Scannerfile: %s Error: %s\n", FileName, strerror(errno));
        return false;
    }

    while (write(fd_scan, " ", 1) < 0 && errno == EINTR)
    {
        LogFile::ErrorMessage("Could not write to Scannerfile: %s\n", FileName );
        return false;
    }

    //set-group-ID and group-execute
    while (fstat(fd_scan, &fstatpuff) < 0 && errno == EINTR)
    {
        LogFile::ErrorMessage("fstat error\n");
        return false;
    }
    while (fchmod(fd_scan, (fstatpuff.st_mode & ~S_IXGRP) | S_ISGID) < 0 && errno == EINTR)
    {
        LogFile::ErrorMessage("fchmod error\n");
        return false;
    }

    if (fcntl(fd_scan, F_SETLK, &lock) < 0)
    {
        LogFile::ErrorMessage("Could not lock Scannerfile: %s\n", FileName);
        return false;
    }

    if (lseek(fd_scan, 0, SEEK_SET) < 0)
    {
        LogFile::ErrorMessage("Could not lseek Scannerfile: %s\n", FileName);
        return false;
    }

    return true;
}


//Unlock file
bool ScannerFileHandler::UnlockFile()
{
    struct flock lock;
    lock.l_type   = F_UNLCK;
    lock.l_start  = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len    = 0;

    //Partial unlock file
    if (fcntl(fd_scan, F_SETLK, &lock) < 0)
    {
        LogFile::ErrorMessage("Could not unlock Scannerfile: %s\n", strerror(errno));
        exit(0);
    }

    return true;
}


bool ScannerFileHandler::DeleteFile()
{
    while (close(fd_scan) < 0 && errno == EINTR)
    {
        LogFile::ErrorMessage("Could not close() Scannerfile: %s\n", strerror(errno));
        exit(0);
    }

    while (unlink(FileName) < 0)
    {
        //File already deleted
        if (errno == ENOENT) break;
        //Retry if signal received or file busy
        if (errno == EINTR || errno == EBUSY) continue;

	LogFile::ErrorMessage("Could not delete Scannerfile: %s\n", strerror(errno));
	exit(0);
    }

    return true;
}

bool ScannerFileHandler::ReinitFile()
{
    struct flock lock;
    struct stat fstatpuff;
    int ret;

    if (lseek(fd_scan, 0, SEEK_SET) < 0)
    {
        LogFile::ErrorMessage("Could not lseek Scannerfile: %s\n", strerror(errno));
        exit(0);
    }

    while (ftruncate(fd_scan, 0) < 0 && errno == EINTR)
    {
        LogFile::ErrorMessage("Could not truncate file: %s\n", strerror(errno));
        exit(0);
    }

    while (write(fd_scan, " ", 1) < 0 && errno == EINTR)
    {
        LogFile::ErrorMessage("Could not write file: %s\n", strerror(errno));
        exit(0);
    }

    //set-group-ID and group-execute
    while (fstat(fd_scan, &fstatpuff) < 0 && errno == EINTR)
    {
        LogFile::ErrorMessage("Could not fstat Scannerfile: %s\n", strerror(errno));
        exit(0);
    }
    while (fchmod(fd_scan, (fstatpuff.st_mode & ~S_IXGRP) | S_ISGID) < 0 && errno == EINTR)
    {
        LogFile::ErrorMessage("Could not fchmod Scannerfile: %s\n", strerror(errno));
        exit(0);
    }

    FileLength = 0;

    lock.l_type   = F_WRLCK;
    lock.l_start  = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len    = MAXFILELOCKSIZE;

    if (fcntl(fd_scan, F_SETLK, &lock) < 0)
    {
        LogFile::ErrorMessage("Could not lock Scannerfile: %s\n", strerror(errno));
        exit(0);
    }

    if (lseek(fd_scan, 0, SEEK_SET) < 0)
    {
        LogFile::ErrorMessage("Could not lseek Scannerfile: %s\n", strerror(errno));
        exit(0);
    }

    return true;
}

bool ScannerFileHandler::SetFileSize( long long ContentLengthT )
{
    if (lseek(fd_scan, (off_t)ContentLengthT-1, SEEK_SET) < 0)
    {
        LogFile::ErrorMessage("Could not lseek Scannerfile: %s\n", strerror(errno));
        return false;
    }

    while (write(fd_scan, "1", 1) < 0 && errno == EINTR)
    {
        LogFile::ErrorMessage("Could not write to Scannerfile: %s\n", strerror(errno));
        return false;
    }

    if (lseek(fd_scan, 0, SEEK_SET) < 0)
    {
        LogFile::ErrorMessage("Could not lseek Scannerfile: %s\n", strerror(errno));
        return false;
    }

    return true;
}

bool ScannerFileHandler::TruncateFile( long long ContentLengthT )
{
    while (ftruncate(fd_scan, (off_t)ContentLengthT) < 0 && errno == EINTR)
    {
        LogFile::ErrorMessage("Could not truncate Scannerfile: %s\n", strerror(errno));
        exit(0);
    }

    return true;
}

bool ScannerFileHandler::ExpandFile( string *dataT, bool unlockT )
{
    int total_written = 0;
    int len = dataT->length();
    int ret;

    FileLength += len;

    //Handle partial write if interrupted by signal!
    while (total_written < len)
    {
        while ((ret = write(fd_scan, dataT->substr(total_written).c_str(), len - total_written)) < 0)
        {
            if (errno == EINTR) continue;

            LogFile::ErrorMessage("ExpandFile Could not write: %s %s\n", FileName, strerror(errno));
            return false;
        }

        total_written += ret;
    }

    if (unlockT == true)
    {
        struct flock lock;
        lock.l_type   = F_UNLCK;
        lock.l_start  = 0;                        // byte-offset
        lock.l_whence = SEEK_SET;
        lock.l_len    = FileLength;               // number of bytes; 0 = EOF

        //partly unlock
        if (fcntl(fd_scan, F_SETLK, &lock) < 0)
        {
            LogFile::ErrorMessage("Could not unlock file: %s\n", FileName);
            return false;
        }
    }

    return true;
}

char* ScannerFileHandler::GetFileName()
{
    return FileName;
}

bool ScannerFileHandler::InitDatabase()
{
    return false;
}
bool ScannerFileHandler::ReloadDatabase()
{
    return false;
}
void ScannerFileHandler::FreeDatabase()
{
}
int ScannerFileHandler::Scanning()
{
    return -1;
}

//Constructor
ScannerFileHandler::ScannerFileHandler()
{

}


//Destructor
ScannerFileHandler::~ScannerFileHandler()
{
}
