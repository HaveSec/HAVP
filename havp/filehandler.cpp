/***************************************************************************
                          filehandler.cpp  -  description
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



#include "filehandler.h"

//Danny
void FileHandler::SearchReplace(std::string & source, std::string & search, std::string & replace)
{
    int position;
    position = source.find(search);
    while (position != -1)
    {
        source.replace(position, search.size(), replace);
        position = source.find(search);
    }
}

//Danny
long FileHandler::FileSize(const char* filename)
{
    filebuf *pbuf;
    long size;

    ifstream file;

    file.open (filename);
    if (!file) {
        LogFile::ErrorMessage("Error reading size of template %s\n", filename);
        return 0;
    }

    pbuf = file.rdbuf();
    size = pbuf->pubseekoff (0, ios::end, ios::in);

    file.close();

    return size;
}

//Danny
bool FileHandler::FileRead(const char* filename, char* buffer, long size)
{
    filebuf *pbuf;

    ifstream file;

    file.open (filename);
    if (!file) {
        LogFile::ErrorMessage("Error reading template %s\n", filename);
        return false;
    }

    pbuf = file.rdbuf();
    pbuf->sgetn(buffer, size);

    file.close();

    return true;
}
