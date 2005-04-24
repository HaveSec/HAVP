/***************************************************************************
                          default.h  -  description
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


#ifndef DEFAULT_H
#define DEFAULT_H


//Change to User and Group
#define USER "nobody"
#define GROUP "nogroup"

//Fork max server
#define SERVERNUMBER 35

//Make daemon
#define DAEMON

//Transparent Proxy
//#define TRANSPARENT

//Parent Proxy (Name)
//#define PARENTPROXY "localhost"
//#define PARENTPORT 3128

//Don't let pass when scanner failed
#define CATCHONSCANNERERROR

//Access log directory
#define ACCESSLOG "/var/log/havp/access.log"

//Error log directory
#define ERRORLOG "/var/log/havp/havp.log"

//Time format
#define TIMEFORMAT "%d/%m/%Y %H:%M:%S"

//Port of proxy server
#define PORT 8000

//Address to bind to for listening: NULL for any, "127.0.0.1" for local, or specific address
#define BIND_ADDRESS ( (char *) NULL )

//Temporary scan file - File name characters followed by six Xs 
//Hard lock must be enabled
#define SCANTEMPFILE "/tmp/virus/havp-XXXXXX"
//Maximum length of SCANTEMPFILE
#define MAXSCANTEMPFILELENGTH 200 

//Display initial messages
#define DISPLAYINITIALMESSAGES

//Disable Encoding - This is a work around for the IE 5.5 bug
#define NOENCODING 1

//Maximum client connection waiting for accept
#define MAXCONNECTIONS  1024

//Bytes which will be hold back
#define KEEPBACKBUFFER 50005

//Maximum bytes received in one request
#define MAXRECV   50000

//Maximum logfile line length
#define STRINGLENGTH 1000

//Maximum hardlock size - do not change
#define MAXFILELOCKSIZE 1000000000

//CLAMLIB Config -----------------------------------

//max files scanned in archiv
#define MAXSCANFILES 1000

//maximal archived file size in MB
#define MAXARCHIVFILESIZE 10

//maximal recursion level in Archiv
#define MAXRECLEVEL 5

//maximal compression ratio
#define MAXRATIO 200

//disable memory limit for bzip2 scanner
#define ARCHIVEMEMLIM 0

// CLAMLIB End -------------------------------------


// HTML Error String

#define ERRORHEADER "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\n\r\n";

#define DNSERROR "<html><body><h1>Could not resolve DNS name!</h1></body></html>"

#define VIRUSINSERTPOSITION  22
#define VIRUSFOUND   "<html><body><h1>Virus  found</h1></body></html>";

#define SCANNERERROR "<html><body><h1>Could not scan file: </h1></body></html>";
#define ERRORINSERTPOSITION  37
#endif
