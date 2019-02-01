/***************************************************************************
                          default.h  -  description
                             -------------------
    begin                : 2005/02/12
    last                 : 2019/02/02
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

#define VERSION "0.93"

//##############################################################
//Define if you want to rewrite a URL
//#define REWRITE URLRewrite["havp"]="www.havp.org"; URLRewrite["www.havp"]="www.havp.org";

//##############################################################
//Parameters in Configurationfile

#define CONFIGPARAMS \
 "WHITELISTFIRST","TEMPDIR","RANGE", "PRELOADZIPHEADER", "USER","GROUP", \
 "SERVERNUMBER","PORT","BIND_ADDRESS","SOURCE_ADDRESS","KEEPBACKBUFFER", \
 "KEEPBACKTIME","TRICKLING","TRICKLINGBYTES","MAXSCANSIZE","WHITELIST","BLACKLIST","PIDFILE", \
 "DAEMON","TRANSPARENT","LOG_OKS","ACCESSLOG","VIRUSLOG","ERRORLOG","TIMEFORMAT","LOGLEVEL", \
 "USESYSLOG","SYSLOGNAME","SYSLOGFACILITY","SYSLOGLEVEL","SYSLOGVIRUSLEVEL","IGNOREVIRUS", \
 "DISPLAYINITIALMESSAGES","DBRELOAD","SCANTEMPFILE","TEMPLATEPATH","DISABLELOCKINGFOR", \
 "PARENTPROXY","PARENTPORT","MAXSERVERS","FORWARDED_IP","X_FORWARDED_FOR","FAILSCANERROR", \
 "SSLTIMEOUT", \
 "MAXDOWNLOADSIZE","SCANNERTIMEOUT","STREAMUSERAGENT","STREAMSCANSIZE","SCANIMAGES", \
 "SKIPMIME","SCANMIME", \
 "ENABLECLAMLIB","CLAMDBDIR","CLAMBLOCKBROKEN","CLAMBLOCKMAX","CLAMBLOCKENCRYPTED", \
 "CLAMMAXFILES","CLAMMAXFILESIZE","CLAMMAXRECURSION","CLAMMAXSCANSIZE", \
 "ENABLEAVG","AVGSERVER","AVGPORT", \
 "ENABLEAVESERVER","AVESOCKET", \
 "ENABLEFPROT","FPROTSERVER","FPROTPORT","FPROTOPTIONS", \
 "ENABLETROPHIE","TROPHIEMAXFILES","TROPHIEMAXFILESIZE","TROPHIEMAXRATIO", \
 "ENABLENOD32","NOD32SOCKET","NOD32VERSION", \
 "ENABLECLAMD","CLAMDSOCKET","CLAMDSERVER","CLAMDPORT", \
 "ENABLESOPHIE","SOPHIESOCKET", \
 "ENABLEAVAST","AVASTSOCKET","AVASTSERVER","AVASTPORT", \
 "ENABLEARCAVIR","ARCAVIRSOCKET","ARCAVIRVERSION", \
 "ENABLEDRWEB","DRWEBSOCKET","DRWEBSERVER","DRWEBPORT","DRWEBHEURISTIC","DRWEBMALWARE", \
 "PARENTUSER", "PARENTPASSWORD"
//SCANNERS


//##############################################################
//Configuration not setable in havp.config

//CONNTIMEOUT in seconds
#define CONNTIMEOUT 60

//RECVTIMEOUT in seconds
#define RECVTIMEOUT 120

//SENDTIMEOUT in seconds
#define SENDTIMEOUT 120

//Maximum client connection waiting for accept
#define MAXCONNECTIONS 1024

//Maximum bytes received in one request
#define MAXRECV 14600

//Maximum logfile line length
#define STRINGLENGTH 1000

//Maximum hardlock size - do not change
#define MAXFILELOCKSIZE 1000000000

//Valid Methods
#define METHODS \
 "GET","POST","HEAD","CONNECT","PUT","TRACE","PURGE","OPTIONS","UNLOCK", \
 "SEARCH","PROPFIND","BPROPFIND","PROPPATCH","BPROPPATCH","MKCOL","COPY", \
 "BCOPY","MOVE","LOCK","BMOVE","DELETE","BDELETE","SUBSCRIBE","UNSUBSCRIBE", \
 "POLL","REPORT","ERROR","NONE","MKACTIVITY","CHECKOUT","MERGE"

//Maximum length of SCANTEMPFILE
#define MAXSCANTEMPFILELENGTH 200

//Maximum length of http headers
#define MAXHTTPHEADERLENGTH 65536

// HTML Error String
#define ERROR_DNS	"dns.html"
#define VIRUS_FOUND	"virus.html"
#define ERROR_SCANNER	"scanner.html"
#define ERROR_DOWN	"down.html"
#define ERROR_INVALID	"invalid.html"
#define ERROR_REQUEST	"request.html"
#define ERROR_BODY	"error.html"
#define ERROR_BLACKLIST	"blacklist.html"
#define ERROR_MAXSIZE	"maxsize.html"

#include "_default.h"

#endif
