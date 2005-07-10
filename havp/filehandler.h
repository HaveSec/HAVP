/***************************************************************************
                          filehandler.h  -  description
                             -------------------
    begin                : Fre Jul 1 2005
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


/***************************************************************************
                          filehandler.h.h  -  description
                             -------------------
    begin                : Fre Jul 1 2005
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


#ifndef FILEHANDLER_H
#define FILEHANDLER_H

//#include <iostream>
#include <fstream>
#include "default.h"
#include "logfile.h"

using namespace std;


//Danny
class FileHandler {

private:

public:

    long FileSize(const char* filename);

    bool FileRead(const char* filename, char* buffer, long size);

    void SearchReplace(std::string & source, std::string & search, std::string & replace);

};

#endif
