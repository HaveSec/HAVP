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

pthread_mutex_t GenericScanner::scan_mutex = PTHREAD_MUTEX_INITIALIZER;

bool GenericScanner::PrepareScanning( void *GenericScannerT )
{

if ( InitSelfEngine() == false){
  return false; }

if (pthread_create( &ScannerThread, NULL, GenericScanner::CallScanner , GenericScannerT )){
   return false; }

return true;
}




void *GenericScanner::CallScanner ( void *GenericScannerT ) {

((GenericScanner*)GenericScannerT)->Scanning();

pthread_exit(0);

return GenericScannerT;
}


string GenericScanner::ReadScannerAnswer (){

string Answer;

      pthread_mutex_lock( &scan_mutex );
      Answer = ScannerAnswer;
      pthread_mutex_unlock( &scan_mutex );

return Answer;
}


string GenericScanner::ReadErrorAnswer (){

string Answer;

      pthread_mutex_lock( &scan_mutex );
      Answer = ErrorAnswer;
      pthread_mutex_unlock( &scan_mutex );

return Answer;
}

void GenericScanner::WriteScannerAnswer (){

cout << ScannerAnswer << endl;

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


