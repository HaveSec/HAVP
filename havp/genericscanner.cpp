/***************************************************************************
                          genericscanner.cpp  -  description
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

#include "genericscanner.h"
#include <sys/types.h>
#include <unistd.h>

bool GenericScanner::PrepareScanning( void *GenericScannerT )
{


if ( InitSelfEngine() == false){
  return false; }

 if (( ScannerPid = fork() ) < 0)
 {
   return false; //Parent error
 } else if ( ScannerPid != 0) {
  //Parent
  return true;
 }
 //Child
  
((GenericScanner*)GenericScannerT)->Scanning();

 exit (-3); //should never get here!!
 return false;
}



string GenericScanner::ReadScannerAnswer (){

  string Answer = ScannerAnswer;
      
return Answer;
}


//Constructor
GenericScanner::GenericScanner( )
{
 ScannerAnswer = "";
}

//Destructor
GenericScanner::~GenericScanner( )
{

}


