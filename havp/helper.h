/***************************************************************************
                          helper.h  -  description
                             -------------------
    begin                : Sa M� 5 2005
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

#ifndef HELPER_H
#define HELPER_H

#include <unistd.h>
#include <string>

bool MakeDaemon();
bool HardLockTest();
bool ChangeUserAndGroup( string usr, string grp );
bool WritePidFile( pid_t pid );
int InstallSignal( int level );

#endif
