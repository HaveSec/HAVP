/***************************************************************************
                          drwebscanner.cpp  -  description
                             -------------------
    begin                : Sa Feb 12 2005
    copyright            : (C) 2005 by Christian Hilgers
    email                : christian@havp.org
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include "drwebscanner.h"

/* drweb-clients-4.33-sources */

/* -- SCAN_COMMANDS -------------------------------------------------- */
#define DRWEBD_SCAN_CMD             (1)     /* scan file, buffer or diskfile */
#define DRWEBD_VERSION_CMD          (2)     /* get daemon version */
#define DRWEBD_BASEINFO_CMD         (3)     /* get info about viruses bases */
#define DRWEBD_IDSTRING_CMD         (4)     /* get id-string of daemon */
#define DRWEBD_SCANPART_CMD         (5)     /* scan part of diskfile */
#define DRWEBD_SPAMCHECK_CMD        (6)     /* check mail by anti-spam */
#define DRWEBD_GET_UUID_CMD         (7)     /* get daemon uuid (unique for each customer) */

/* -- SCAN_OPTIONS ---------------------------------------------------- */
#define DRWEBD_RETURN_VIRUSES       (1<<0)   /* ask daemon return to us viruses names from report */
#define DRWEBD_RETURN_REPORT        (1<<1)   /* ask daemon return to us return report line */
#define DRWEBD_RETURN_CODES         (1<<2)   /* ask daemon return to us return codes */
#define DRWEBD_HEURISTIC_ON         (1<<3)   /* enables heuristic in finding module */
#define DRWEBD_RULE_FILTER_ON       (1<<5)   /* Unix only: enables FilterRules in daemon */
#define DRWEBD_INFECTED_CURE        (1<<6)   /* Unix only: try to cure infected files - if fails file decided incureable */ 
#define DRWEBD_INFECTED_MOVE        (1<<7)   /* move infected files */
#define DRWEBD_INFECTED_RENAME      (1<<8)   /* just rename infected files */
#define DRWEBD_INFECTED_DELETE      (1<<9)   /* delete infected files */
#define DRWEBD_INCURABLE_MOVE       (1<<10)  /* move incureable files */
#define DRWEBD_INCURABLE_RENAME     (1<<11)  /* just rename incureable files */
#define DRWEBD_INCURABLE_DELETE     (1<<12)  /* delete incureable files */
#define DRWEBD_SUSPECTED_MOVE       (1<<13)  /* move suspicious files */
#define DRWEBD_SUSPECTED_RENAME     (1<<14)  /* just rename suspicious files */
#define DRWEBD_SUSPECTED_DELETE     (1<<15)  /* delete suspicious files */
#define DRWEBD_ARCHIVE_MOVE         (1<<16)  /* move archive with infected/suspected files */
#define DRWEBD_ARCHIVE_RENAME       (1<<17)  /* rename archive with infected/suspected files */
#define DRWEBD_ARCHIVE_DELETE       (1<<18)  /* delete archive with infected/suspected files */
#define DRWEBD_IS_MAIL              (1<<19)  /* Unix only: say to daemon that format is "archive MAIL" */
#define DRWEBD_DONT_CHANGEMAIL      (1<<21)  /* Unix only: say to daemon that mail file cannot be changed */
#define DRWEBD_RETURN_SHORT_VIRUSES (1<<22)  /* ask daemon return to us pairs of virusnames and infection type {K|M|S} */
#define DRWEBD_RETURN_FILTER_RULE   (1<<23)  /* ask daemon return to us filtering rule that has been altered */
#define DRWEBD_HAVE_ENVELOPE        (1<<24)  /* say to daemon that filter will send mail envelope */
#define DRWEBD_CHECK_ARX            (1<<25)  /* Windows only: say to WinEngine scans into archives (RAR,ZIP etc) */
#define DRWEBD_USE_TCPNODELAY       (1<<26)  /* use TCP_NODELAY option */
#define DRWEBD_HAVE_EXTENDED        (1<<31)  /* client knows about extended options */

/* -- SCAN_EXTENDED_OPTIONS ------------------------------------------- */
#define DRWEBD_EXT_ADWARE_IGNORE    (1<<1)   /* ignore adware */
#define DRWEBD_EXT_ADWARE_MOVE      (1<<2)   /* move adware */
#define DRWEBD_EXT_ADWARE_RENAME    (1<<3)   /* rename adware */
#define DRWEBD_EXT_ADWARE_DELETE    (1<<4)   /* delete adware */
#define DRWEBD_EXT_DIALER_IGNORE    (1<<5)   /* ignore adware */
#define DRWEBD_EXT_DIALER_MOVE      (1<<6)   /* move adware */
#define DRWEBD_EXT_DIALER_RENAME    (1<<7)   /* rename adware */
#define DRWEBD_EXT_DIALER_DELETE    (1<<8)   /* delete adware */
#define DRWEBD_EXT_JOKE_IGNORE      (1<<9)   /* ignore adware */
#define DRWEBD_EXT_JOKE_MOVE        (1<<10)   /* move adware */
#define DRWEBD_EXT_JOKE_RENAME      (1<<11)   /* rename adware */
#define DRWEBD_EXT_JOKE_DELETE      (1<<12)   /* delete adware */
#define DRWEBD_EXT_RISKWARE_IGNORE  (1<<13)   /* ignore adware */
#define DRWEBD_EXT_RISKWARE_MOVE    (1<<14)   /* move adware */
#define DRWEBD_EXT_RISKWARE_RENAME  (1<<15)   /* rename adware */
#define DRWEBD_EXT_RISKWARE_DELETE  (1<<16)   /* delete adware */
#define DRWEBD_EXT_HACKTOOL_IGNORE  (1<<17)   /* ignore adware */
#define DRWEBD_EXT_HACKTOOL_MOVE    (1<<18)   /* move adware */
#define DRWEBD_EXT_HACKTOOL_RENAME  (1<<19)   /* rename adware */
#define DRWEBD_EXT_HACKTOOL_DELETE  (1<<20)   /* delete adware */

/* -- SCAN_RESULT ----------------------------------------------------- */
#define DERR_NOERROR                (0)     /*= 0x00000000 */
#define DERR_READ_ERR               (1<<0)  /*= 0x00000001 */
#define DERR_WRITE_ERR              (1<<1)  /*= 0x00000002 */               
#define DERR_NOMEMORY               (1<<2)  /*= 0x00000004 */            
#define DERR_CRC_ERROR              (1<<3)  /*= 0x00000008 */            
#define DERR_READSOCKET             (1<<4)  /*= 0x00000010 */             
#define DERR_KNOWN_VIRUS            (1<<5)  /*= 0x00000020 */            
#define DERR_UNKNOWN_VIRUS          (1<<6)  /*= 0x00000040 */               
#define DERR_VIRUS_MODIFICATION     (1<<7)  /*= 0x00000080 */             
#define DERR_HAVE_CURED             (1<<8)  /*= 0x00000100 */             
#define DERR_TIMEOUT                (1<<9)  /*= 0x00000200 */              
#define DERR_SYMLINK                (1<<10) /*= 0x00000400 */            
#define DERR_NO_REGFILE             (1<<11) /*= 0x00000800 */             
#define DERR_SKIPPED                (1<<12) /*= 0x00001000 */           
#define DERR_TOO_BIG                (1<<13) /*= 0x00002000 */            
#define DERR_TOO_COMPRESSED         (1<<14) /*= 0x00004000 */           
#define DERR_BAD_CALL               (1<<15) /*= 0x00008000 */            
#define DERR_EVAL_KEY               (1<<16) /*= 0x00010000 */            
#define DERR_FILTER_REJECT          (1<<17) /*= 0x00020000 */           
#define DERR_ARCHIVE_LEVEL          (1<<18) /*= 0x00040000 */
#define DERR_HAVE_DELETED           (1<<19) /*= 0x00080000 */
#define DERR_IS_CLEAN               (1<<20) /*= 0x00100000 */
#define DERR_LICENSE_ERROR          (1<<21) /*= 0x00200000 */
#define DERR_ADWARE                 (1<<22) /*= 0x00400000 */
#define DERR_DIALER                 (1<<23) /*= 0x00800000 */
#define DERR_JOKE                   (1<<24) /*= 0x01000000 */
#define DERR_RISKWARE               (1<<25) /*= 0x02000000 */
#define DERR_HACKTOOL               (1<<26) /*= 0x04000000 */
#define DERR_MASK                   (0x0FFFFFFF)
#define DERR_NON_DAEMON_ERROR       (~DERR_MASK)
#define DERR_INFECTED               (DERR_KNOWN_VIRUS | DERR_VIRUS_MODIFICATION)
#define DERR_SUSPICIOUS             (DERR_UNKNOWN_VIRUS)
#define DERR_MALWARE                (DERR_ADWARE | DERR_DIALER | DERR_JOKE | DERR_RISKWARE | DERR_HACKTOOL)
#define DERR_VIRUS_MASK             (DERR_INFECTED | DERR_SUSPICIOUS | DERR_MALWARE)
#define DERR_SKIP_OBJECT            (DERR_SYMLINK | DERR_NO_REGFILE | DERR_SKIPPED | DERR_CRC_ERROR | DERR_TIMEOUT)
#define DERR_ARCHIVE_RESTRICTION    (DERR_TOO_BIG | DERR_TOO_COMPRESSED | DERR_ARCHIVE_LEVEL)
#define DERR_DAEMON_ERROR           (DERR_READ_ERR | DERR_WRITE_ERR | DERR_NOMEMORY | DERR_READSOCKET | DERR_BAD_CALL)


bool DrwebScanner::InitDatabase()
{
    return true;
}


int DrwebScanner::ReloadDatabase()
{
    return 0;
}


string DrwebScanner::Scan( const char *FileName )
{
    if ( ConnectScanner() == false )
    {
        ScannerAnswer = "2Could not connect to scanner socket";
        return ScannerAnswer;
    }

    //Construct command for scanner
    int scan_cmd = htonl( DRWEBD_SCAN_CMD );
    int scan_flags = htonl( Opts );
    int scan_slen = htonl( strlen(FileName) );
    int scan_null = htonl( 0x0000 );

    if ( Scanner.Send( (const char*)&scan_cmd, sizeof(scan_cmd) ) == false ||
         Scanner.Send( (const char*)&scan_flags, sizeof(scan_flags) ) == false ||
         Scanner.Send( (const char*)&scan_slen, sizeof(scan_slen) ) == false ||
         Scanner.Send( FileName, strlen(FileName) ) == false ||
         Scanner.Send( (const char*)&scan_null, sizeof(scan_null) ) == false )
    {
        Scanner.Close();
        LogFile::ErrorMessage("Drweb: Could not write command to scanner\n");
        ScannerAnswer = "2Scanner connection failed";
        return ScannerAnswer;
    }

    int scan_rc, scan_vnum;
    ssize_t read;

    if ( (read = recv( Scanner.sock_fd, &scan_rc, sizeof(scan_rc), 0 )) != sizeof(scan_rc) )
    {
        Scanner.Close();
        LogFile::ErrorMessage("Drweb: Could not read scanner response (rc, read: %d errno: %d)\n", read, errno);
        ScannerAnswer = "2Could not read scanner response";
        return ScannerAnswer;
    }
    if ( (read = recv( Scanner.sock_fd, &scan_vnum, sizeof(scan_vnum), 0 )) != sizeof(scan_vnum) )
    {
        Scanner.Close();
        LogFile::ErrorMessage("Drweb: Could not read scanner response (vnum, read: %d errno: %d)\n", read, errno);
        ScannerAnswer = "2Could not read scanner response";
        return ScannerAnswer;
    }

    scan_rc = ntohl(scan_rc);
    scan_vnum = ntohl(scan_vnum);

    if ( scan_rc == DERR_IS_CLEAN ||
         scan_rc & DERR_ARCHIVE_RESTRICTION ||
         scan_rc & DERR_SKIP_OBJECT
         )
    {
        Scanner.Close();
        ScannerAnswer = "0Clean";
        return ScannerAnswer;
    }

    char code[512];
    memset(&code, 0, sizeof(code));
    snprintf(code, 500, "%d", scan_rc);
    string Code = code;

    if (scan_rc & DERR_INFECTED || scan_rc & DERR_SUSPICIOUS ||
        (Params::GetConfigBool("DRWEBMALWARE") && scan_rc & DERR_MALWARE) )
    {
        ScannerAnswer = "1unknown (" + Code + ")";
        string VirusNames = "";

        for (int i=0;i<scan_vnum;i++)
        {
            char vname[256];
            memset(&vname, 0, sizeof(vname));

            if ( (read = recv( Scanner.sock_fd, &scan_slen, sizeof(scan_slen), 0 )) != sizeof(scan_slen) )
            {
                Scanner.Close();
                LogFile::ErrorMessage("Drweb: Could not read scanner response (vnamelen, read: %d errno: %d)\n", read, errno);
                return ScannerAnswer;
            }

            scan_slen = ntohl(scan_slen);
            if ( scan_slen > 250 ) scan_slen = 250;

            if ( (read = recv( Scanner.sock_fd, &vname, scan_slen, 0 )) != scan_slen )
            {
                Scanner.Close();
                LogFile::ErrorMessage("Drweb: Could not read scanner response (vname, read: %d errno: %d)\n", read, errno);
                return ScannerAnswer;
            }

            string tmp = vname;
            if (i==0) { VirusNames = tmp; } else { VirusNames += ", " + tmp; }
        }

        SearchReplace( VirusNames, "infected with ", "" );
        if ( VirusNames != "" ) ScannerAnswer = "1" + VirusNames;
    }
    else if (scan_rc & DERR_DAEMON_ERROR)
    {
        if (scan_rc & DERR_READ_ERR)
        {
            ScannerAnswer = "2Daemon could not read tempfile";
        }
        else
        {
            ScannerAnswer = "2Daemon error (" + Code + ")";
        }
    }
    else
    {
        ScannerAnswer = "2Unknown error (" + Code + ")";
    }

    Scanner.Close();
    return ScannerAnswer;
}


void DrwebScanner::FreeDatabase()
{
}


bool DrwebScanner::ConnectScanner()
{
    bool SockAnswer;

    if ( UseSocket )
    {
        SockAnswer = Scanner.ConnectToSocket( Params::GetConfigString("DRWEBSOCKET"), 1 );
    }
    else
    {
        SockAnswer = Scanner.ConnectToServer();
    }

    if ( SockAnswer == false )
    {
        //Prevent log flooding, show error only once per minute
        if ( (LastError == 0) || (LastError + 60 < time(NULL)) )
        {
            LogFile::ErrorMessage("Drweb: Could not connect to scanner! Scanner down?\n");
            LastError = time(NULL);
        }

        return false;
    }

    return true;
}


//Constructor
DrwebScanner::DrwebScanner()
{
    ScannerName = "Drweb Socket Scanner";
    ScannerNameShort = "Drweb";

    LastError = 0;

    if ( Params::GetConfigString("DRWEBSERVER") != "" )
    {
        UseSocket = false;

        if ( Scanner.SetDomainAndPort( Params::GetConfigString("DRWEBSERVER"), Params::GetConfigInt("DRWEBPORT") ) == false )
        {
            LogFile::ErrorMessage("Drweb: Could not resolve scanner host\n");
        }
    }
    else
    {
        UseSocket = true;
    }

    Opts = DRWEBD_RETURN_VIRUSES;

    if ( Params::GetConfigBool("DRWEBHEURISTIC") == true )
    {
        Opts = Opts | DRWEBD_HEURISTIC_ON;
    }

    ScannerAnswer.reserve(100);
}


//Destructor
DrwebScanner::~DrwebScanner()
{
}

