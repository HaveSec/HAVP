####### kdevelop will overwrite this part!!! (begin)##########
bin_PROGRAMS = havp

## INCLUDES were found outside kdevelop specific part

havp_SOURCES = helper.cpp proxyhandler.cpp logfile.cpp clamlibscanner.cpp scannerfilehandler.cpp genericscanner.cpp connectiontoserver.cpp connectiontobrowser.cpp httphandler.cpp sockethandler.cpp havp.cpp 
havp_LDADD   = -lclamav -lpthread

SUBDIRS = docs 

EXTRA_DIST = havp.cpp sockethandler.cpp sockethandler.h default.h httphandler.cpp httphandler.h connectiontobrowser.cpp connectiontobrowser.h connectiontoserver.cpp connectiontoserver.h genericscanner.cpp genericscanner.h scannerfilehandler.cpp scannerfilehandler.h clamlibscanner.cpp clamlibscanner.h logfile.cpp logfile.h proxyhandler.cpp proxyhandler.h helper.cpp helper.h 

####### kdevelop will overwrite this part!!! (end)############
# set the include path found by configure
INCLUDES= $(all_includes)
 
# the library search path.
havp_LDFLAGS = $(all_libraries) 
                                                                                
