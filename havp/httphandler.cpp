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
int poscount = 0;
ssize_t read;
string tempheader="";

*headerT="";

if ( ( read = SocketHandler::Recv( &tempheader, false ) ) <= 0 ) {
   return false; }

while ( (position = tempheader.find ("\r\n\r\n")) == string::npos )
{
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

//Read last part of header
if ( SocketHandler::RecvLength(headerT, position-poscount+2 ) == false ) {
  return false; }

//Read last \r\n
if ( SocketHandler::RecvLength(&tempheader, 2 ) == false ){
  return false; }

return true;
}


//Split header to tokens
bool HTTPHandler::TokenizeHeader(string *linesT, const char *delimitersT )
 {

 //delete tokens
 tokens.clear();

  string::size_type lastposition = 0;
  string::size_type length = linesT->length();
  string::size_type position = linesT->find (delimitersT, 0);

  if ( position == string::npos )
  {
    return false;
  }
  
    while (position != string::npos && lastposition != length)
    {
        tokens.push_back(linesT->substr(lastposition, position - lastposition + 2 ));

        lastposition = position + 2;

        position = linesT->find( delimitersT, lastposition);
    }

 return true;
}


//Get Content Length
unsigned long HTTPHandler::GetContentLength(string* HeaderT)
{
string::size_type begin;

    if( (begin = HeaderT->find("Content-Length: ",0) ) != string::npos)
    {
      begin = begin + 16;
       string::size_type end = HeaderT->find("\r\n", begin);
       string::size_type length = end - begin;
       string Length = HeaderT->substr(begin, length );

       //danger - ask for error
       return atol( (char*)Length.c_str() );


    } else {
    return 0;
    }

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
