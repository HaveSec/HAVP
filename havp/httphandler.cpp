/***************************************************************************
                          httphandler.cpp  -  description
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

#include "httphandler.h"

//Read header
bool HTTPHandler::ReadHeader( string *headerT )
{

string::size_type position;
bool WrongHeader=false;
int poscount = 0;
ssize_t read;
string tempheader="";

*headerT="";

if ( ( read = SocketHandler::Recv( &tempheader, false ) ) <= 0 ) {
   return false; }

//Maybe we should also look for \n\n (19.3 RFC 1945 - Tolerant Applications)
while ( (position = tempheader.find ("\r\n\r\n")) == string::npos )
{

 if ( (position = tempheader.find ("\n\n")) != string::npos )
 {
  WrongHeader=true;
  break;
 }
  
 //Header not yet found
 //Read and delete part of header containing no \r\n\r\n
 SocketHandler::RecvLength(headerT, read );

 poscount = poscount + read;

 if( (read = SocketHandler::Recv( &tempheader, false )) <= 0){
   return false; }

 //Connection Close by Peer
 if ( read == 0 ){
  return false; }
}

//cout << tempheader << endl;
//Read last part of header
if ( SocketHandler::RecvLength(headerT, position-poscount+2 ) == false ) {
  return false; }

if ( WrongHeader == false )
  {
  //Read last \r\n
  if ( SocketHandler::RecvLength(&tempheader, 2 ) == false ){
   return false; }
}
return true;
}


//Split header to tokens
bool HTTPHandler::TokenizeHeader(string *linesT, const char *delimitersT )
 {

 string tempToken;
 
 //delete tokens
 tokens.clear();

 //Clear Content Length
 ContentLength=0;

  string::size_type lastposition = 0;
  string::size_type length = linesT->length();

  // Do "Tolerant Applications" - RFC 1945 - Hypertext Transfer Protocol -- HTTP/1.0
  while ( (lastposition = linesT->find ("\r",lastposition)) != string::npos )
  {  
   linesT->replace( lastposition, 1, "" );
  }

  lastposition = 0;
  length = linesT->length();
          
  string::size_type position = linesT->find (delimitersT, 0);

  if ( position == string::npos )
  {
    return false;
  }
  
    while (position != string::npos && lastposition != length)
    {
        tempToken = linesT->substr(lastposition, position - lastposition );

        if ( (lastposition = tempToken.find_last_not_of("\t ")) != string::npos )
        {
        tempToken = tempToken.substr(0,lastposition+1);

        if( (lastposition = tempToken.find("Content-Length: ",0) ) != string::npos)
         {
          lastposition = lastposition + 16;
          string Length = tempToken.substr(lastposition, tempToken.length() );
          if (sscanf( Length.c_str(), "%lu",  &ContentLength) != 1){
          ContentLength=0;
          }

         }       
  
        tokens.push_back(  tempToken+"\r\n" );
        }
        
        lastposition = position + 1;

        position = linesT->find( delimitersT, lastposition);
    }

 return true;
}


//Get Content Length
unsigned long HTTPHandler::GetContentLength( )
{

 return ContentLength;

}


//Read part of Body
ssize_t HTTPHandler::ReadBodyPart( string* bodyT )
{

*bodyT = "";
ssize_t count;

 if ( (count = SocketHandler::Recv( bodyT, true )) == -1){
    return -1;
   }

return count;
}


//Send Header
bool HTTPHandler::SendHeader( string* headerT )
{

if ( SocketHandler::Send( headerT ) == false ) {
  return false; }

  return true;
}

//Constructor
HTTPHandler::HTTPHandler(){
}

//Destructor
HTTPHandler::~HTTPHandler(){
}
