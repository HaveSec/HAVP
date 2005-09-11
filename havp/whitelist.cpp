/***************************************************************************
                          whitelist.cpp  -  description
                             -------------------
    begin                : Don Aug 18 2005
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

#include "whitelist.h"
#include "logfile.h"

#include <stdio.h>
#include <iostream>
#include <fstream>

using namespace std;

bool Whitelist::CreateWhitelist(string WhitelistFileT)
{

 string::size_type i1, i2;
 ifstream Input;
 string Line;
 string Start;
 string URL;
 string Domain;
 char ExactDomain;
 string Path;
 char ExactPath;
 string Toplevel;
 struct WhitelistStruct NewToplevel;
 string::size_type ToplevelCounter;

 Input.open( WhitelistFileT.c_str());

 if(!Input)
 {
   LogFile::ErrorMessage ("Cannot open Whitelist: %s\n", WhitelistFileT.c_str());
   return false;
 }


 while(Input) {
 	getline(Input,Line);
 	Start = Line.substr(0,1);
	i1 = Line.find_first_not_of(" \t");
 	if(Start != "#" && i1 != Line.npos ) {
 	  i2 = Line.find_last_of(" \t");
	  URL = Line.substr(i1,i2-i1);

          if (AnalyseURL( URL, &Toplevel, &Domain, &ExactDomain, &Path, &ExactPath ) == false ) {
            return false;
          }

          ToplevelCounter = 0;
          while (1) {
            if(ToplevelCounter == WhitelistDB.size()){             
              NewToplevel.Toplevel = Toplevel;
              WhitelistDB.push_back( NewToplevel );
            }

             if(WhitelistDB.at(ToplevelCounter).Toplevel == Toplevel){
               InsertURL( &WhitelistDB.at(ToplevelCounter), Domain, ExactDomain, Path, ExactPath );
               break;
             }
            ToplevelCounter++;
           }
        }
 }


 Input.close();

return true;
}


bool Whitelist::AnalyseURL( string UrlT, string *ToplevelT, string *DomainT, char *ExactDomainT, string *PathT, char *ExactPathT )
{

*ToplevelT = "";
*DomainT = "";
*PathT = "";

string::size_type i1;

    if ((i1 = UrlT.find("/")) != string::npos )
    {
     *DomainT = UrlT.substr(0,i1);
     *PathT = UrlT.substr(i1+1, UrlT.size()-i1-1);
    } else {
     *DomainT = UrlT;
     *PathT = "";
    }

    if ((i1 = DomainT->rfind(".")) != string::npos ) //IPs are not detected and last part is handled as toplevel-domain :-(
    {
      *ToplevelT = DomainT->substr( i1+1, DomainT->size()-i1-1);
      *DomainT = DomainT->substr (0,i1+ToplevelT->size()+1);
    } else {
     if ( *DomainT != "*" )
     {
//       LogFile::ErrorMessage ("Whitelist missing Toplevel Domain: %s\n", UrlT.c_str());
       LogFile::ErrorMessage ("Whitelist missing Toplevel Domain: %s\n", DomainT->c_str());
       return false;
     }
    }

*ExactDomainT = CheckItem( DomainT );
if ( (*ExactDomainT != 'l') && (*ExactDomainT != 'n') ) {
  LogFile::ErrorMessage ("Whitelist invalid Domain: %s\n", DomainT->c_str() );
  return false;
} 

*ExactPathT = CheckItem( PathT );
if  (*ExactPathT == 'e') {
  LogFile::ErrorMessage ("Whitelist invalid Path: %s\n", PathT->c_str() );
  return false;
} 

return true;
}



char Whitelist::CheckItem ( string *ItemT )
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
LogFile::ErrorMessage ("Whitelist - To many wildcards in %s\n", ItemT->c_str());
position = 'e';
}

return position;

}

void Whitelist::InsertURL( struct WhitelistStruct *WhitelistDBT, string DomainT, char ExactDomainT, string PathT, char ExactPathT ){

unsigned int DomainCounter = 0;
struct DomainStruct NewDomain;
struct PathStruct NewPath;

          while (1) {

            if(DomainCounter == WhitelistDBT->Domain.size()){             
              NewDomain.Domain = DomainT; 
              NewDomain.exact = ExactDomainT;
              WhitelistDBT->Domain.push_back( NewDomain );
            }

             if(WhitelistDBT->Domain.at(DomainCounter).Domain == DomainT){
              NewPath.Path = PathT; 
              NewPath.exact = ExactPathT;
              WhitelistDBT->Domain.at(DomainCounter).Path.push_back( NewPath ); 
              break;
             }
             DomainCounter++;
          }
}

void Whitelist::DisplayWhitelist( ) {


vector<WhitelistStruct>::iterator ToplevelI;
vector<DomainStruct>::iterator DomainI;
vector<PathStruct>::iterator PathI;

 cout << "Whitelist:" << endl;
 //cout << "Toplevel - Domain - Path" << endl;

 for(ToplevelI = WhitelistDB.begin(); ToplevelI != WhitelistDB.end(); ToplevelI++)
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


}

string Whitelist::DisplayLine( string LineT, char positionT ) {

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


bool Whitelist::URLWhitelisted ( string DomainT, string PathT ) {

vector<WhitelistStruct>::iterator ToplevelI;
vector<DomainStruct>::iterator DomainI;
vector<PathStruct>::iterator PathI;

//Delete / add Path
PathT.erase(0,1);

 for(ToplevelI = WhitelistDB.begin(); ToplevelI != WhitelistDB.end(); ToplevelI++)
 {

//cout << ToplevelI->Toplevel << " " << DomainT.size() - ToplevelI->Toplevel.size() << " " << DomainT.rfind( ToplevelI->Toplevel ) << endl;

   if ((ToplevelI->Toplevel == "") || ( DomainT.rfind( ToplevelI->Toplevel ) == DomainT.size() - ToplevelI->Toplevel.size() )){

     for(DomainI = ToplevelI->Domain.begin(); DomainI != ToplevelI->Domain.end(); DomainI++)
     {

//cout << DomainT << " " << DomainI->Domain << " " << DomainI->exact << endl;

       if( FindString( DomainI->Domain, DomainT, DomainI->exact ) == true) {

        for(PathI = DomainI->Path.begin(); PathI != DomainI->Path.end(); PathI++)
        {

//cout << PathT << " " << PathI->Path << " " << PathI->exact << endl;

          if( FindString( PathI->Path, PathT, PathI->exact ) == true) {
            return true;
          }
        }
      }
     }
   }
  }
return false;
}

bool Whitelist::FindString( string SearchT, string LineT, char positionT ) {

if ( positionT == 'l' ){

//cout << LineT.rfind( SearchT ) << " " << (LineT.size() - SearchT.size()) << endl;

   if ( LineT.rfind( SearchT ) == (LineT.size() - SearchT.size()) ){
     return true;
   }

} else if ( positionT == 'r' ){

   if ( LineT.find( SearchT ) == 0 ){
     return true;
   }

} else if ( positionT == 'b' ){
   if ( LineT.find( SearchT ) != string::npos ){
     return true;
   }
} else if ( positionT == 'n' ){
   if ( LineT == SearchT ){
     return true;
   }
}

return false;
}

Whitelist::Whitelist(){
}
Whitelist::~Whitelist(){
}
