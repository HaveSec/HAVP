/***************************************************************************
                          whitelist.cpp  -  description
                             -------------------
    begin                : Don Aug 18 2005
    copyright            : (C) 2005 by Christian Hilgers
    email                : christian@havp.org
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include "whitelist.h"
#include "logfile.h"

#include <iostream>
#include <fstream>

using namespace std;

bool URLList::CreateURLList(string URLListFileT)
{

 string::size_type i1, i2;
 ifstream Input;
 string Line;
 string Start;
 string URL;
 string Domain;
 struct PathStruct AnalysedURL;

// string::size_type ToplevelCounter;

 Input.open( URLListFileT.c_str());

 if(!Input)
 {
   LogFile::ErrorMessage("Cannot open URLList: %s\n", URLListFileT.c_str());
   return false;
 }


 while(Input) {
 	getline(Input,Line);
 	Start = Line.substr(0,1);
	i1 = Line.find_first_not_of(" \t");
 	if(Start != "#" && i1 != Line.npos ) {
 	  i2 = Line.find_last_of(" \t");
	  URL = Line.substr(i1,i2-i1);

          if (AnalyseURL( URL, &Domain, &AnalysedURL.ExactDomain, &AnalysedURL.Path, &AnalysedURL.ExactPath ) == false ) {
            return false;
          }

//cout << URL << endl << Domain << endl << AnalysedURL.ExactDomain << endl << AnalysedURL.Path << endl << AnalysedURL.ExactPath << endl << "--" << endl;

         URLLists[Domain].push_back( AnalysedURL );

        }

 }


 Input.close();

return true;
}


bool URLList::ReloadURLList( string URLListFileT )
{


map <string, vector <struct PathStruct> >::iterator  URLListsEnum;

 for(URLListsEnum = URLLists.begin(); URLListsEnum != URLLists.end(); URLListsEnum++)
{
	(*URLListsEnum).second.clear();
}
URLLists.clear();

return CreateURLList( URLListFileT );
return true;
}

bool URLList::AnalyseURL( string UrlT, string *DomainT, char *ExactDomainT, string *PathT, char *ExactPathT )
{

*DomainT = "";
*PathT = "";

string::size_type i1;

    if ((i1 = UrlT.find("/")) != string::npos )
    {
     *DomainT = UrlT.substr(0,i1);
     *PathT = UrlT.substr(i1+1, UrlT.size()-i1-1);
    } else {
     *DomainT = UrlT;
     if( UrlT == "") {
       LogFile::ErrorMessage("URLList invalid Domain\n");
      }
     *PathT = "";
    }


*ExactDomainT = CheckItem( DomainT );
if ( (*ExactDomainT != 'l') && (*ExactDomainT != 'n') ) {
  LogFile::ErrorMessage("URLList invalid Domain: %s\n", DomainT->c_str() );
  return false;
} 

*ExactPathT = CheckItem( PathT );
if  (*ExactPathT == 'e') {
  LogFile::ErrorMessage("URLList invalid Path: %s\n", PathT->c_str() );
  return false;
} 

return true;
}



char URLList::CheckItem ( string *ItemT )
{

char position='n';
string character;

if ( ItemT->size() == 0 ) return position;
character = ItemT->substr(0,1);

if( character == "*" ){
 ItemT->erase(0,1);
 position = 'l';
}

if ( ItemT->size() == 0 ) return position;
character = ItemT->substr(ItemT->size()-1,1);

if( character == "*" ){
 ItemT->erase(ItemT->size()-1,1);

 if ( position == 'l' ){
  position = 'b';
 } else {
  position = 'r';
 }
}

if (ItemT->find("*") != string::npos ){
LogFile::ErrorMessage("URLList - Too many wildcards in %s\n", ItemT->c_str());
position = 'e';
}

return position;

}



void URLList::DisplayURLList( ) {

/*
vector<URLListStruct>::iterator ToplevelI;
vector<DomainStruct>::iterator DomainI;
vector<PathStruct>::iterator PathI;

 cout << "URLList:" << endl;
 //cout << "Toplevel - Domain - Path" << endl;

 for(ToplevelI = URLListDB.begin(); ToplevelI != URLListDB.end(); ToplevelI++)
 {
   if ( ToplevelI->Toplevel == "" ){
     cout << " - " << "*" << endl;
   } else {
     cout << " - " << ToplevelI->Toplevel << endl;
   }
   for(DomainI = ToplevelI->Domain.begin(); DomainI != ToplevelI->Domain.end(); DomainI++)
   {
     cout << "   - " << DisplayLine(DomainI->Domain, DomainI->exact) << endl;
     for(PathI = DomainI->Path.begin(); PathI != DomainI->Path.end(); PathI++)
     {
       cout << "       - " << DisplayLine(PathI->Path, PathI->exact) << endl;
     }
   }
 }

*/
}

string URLList::DisplayLine( string LineT, char positionT ) {

string Newline = LineT;

if ( positionT == 'r' ){
Newline = LineT + "*";
} else if ( positionT == 'l' ){
Newline = "*" +LineT;
} else if ( positionT == 'b' ){
Newline = "*" + LineT + "*";
}

return Newline;
}


bool URLList::Search ( string *DomainT, char ExactDomainT, string *PathT ) {

vector<PathStruct>::iterator PathI;

vector <struct PathStruct> *List = &URLLists[*DomainT];

if ( List == NULL ){
return false;
}

 for(PathI = List->begin(); PathI != List->end(); PathI++)
 {

   if ( ( ExactDomainT != 'n' ) && (PathI->ExactDomain != ExactDomainT )){
     continue;
   }


   if( FindString( &PathI->Path, PathT, PathI->ExactPath ) == true) {
            return true;
   }

 }

return false;
}

bool URLList::URLFound ( string DomainT, string PathT ) {

string::size_type pos;

//Delete / add Path
PathT.erase(0,1);

if ( Search ( &DomainT, 'n', &PathT ) == true){
  return true;
 }

while ( (pos = DomainT.find(".")) != string::npos){

	DomainT.erase(0, pos);

	if ( Search ( &DomainT, 'l', &PathT ) == true){
  		return true;
 	}

	DomainT.erase(0, 1);
		if ( Search ( &DomainT, 'l', &PathT ) == true){
 	return true;
 	}
}

DomainT="";
if ( Search ( &DomainT, 'l', &PathT ) == true){
  return true;
 }

return false;
}

bool URLList::FindString( string *SearchT, string *LineT, char positionT ) {

if ( positionT == 'l' ){

//cout << LineT.rfind( SearchT ) << " " << (LineT.size() - SearchT.size()) << endl;

   //Check if SearchT string is larger than LineT
   if (SearchT->size() <= LineT->size() )
   	if ( LineT->rfind( *SearchT ) == (LineT->size() - SearchT->size()) ){
     		return true;
   	}

} else if ( positionT == 'r' ){

   if ( LineT->find( *SearchT ) == 0 ){
     return true;
   }

} else if ( positionT == 'b' ){
   if ( LineT->find( *SearchT ) != string::npos ){
     return true;
   }
} else if ( positionT == 'n' ){
   if ( *LineT == *SearchT ){
     return true;
   }
}

return false;
}

URLList::URLList(){
}
URLList::~URLList(){
}
