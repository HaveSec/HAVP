/***************************************************************************
                          helper.h  -  description
                             -------------------
    begin                : Sa Mär 5 2005
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

#include  <errno.h>

int MakeDeamon();

int HardLockTest ( );

bool ChangeUserAndGroup();

void InstallSignal ();

#endif
