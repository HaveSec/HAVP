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
 string Path;
 string Toplevel;
 bool ToplevelFound;
 struct WhitelistStruct NewToplevel;


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

    if ((i1 = URL.find("/")) == string::npos )
    {
     Domain = URL.substr(0,i1);
     if ((i1 = Domain.rfind(".")) == string::npos ) //IPs are not detected and last part is handled as toplevel-domain :-(
     {
      Toplevel = Domain.substr( i1, Domain.size()-i1-1);
      ToplevelFound = false;

      for(string::size_type i=0;i < WhitelistDB.size(); i++)
      {
       if (Toplevel == WhitelistDB.at(i).Toplevel)
       {
         ToplevelFound = true;
         //Domain, Path;

         for(string::size_type n=0;n <WhitelistDB.at(i).URL.size(); n++)
         {
           if (Domain == WhitelistDB.at(i).URL.at(n).Domain )
           {
             //WhitelistDB.at(i).URL.at(n).Path
           }

         }



       }
      }

     if( ToplevelFound == false )
     {
      NewToplevel.Toplevel = Toplevel;
      WhitelistDB.push_back ( NewToplevel );
     }

     }

    }

 	}
 }


 Input.close();

return true;
}

bool Whitelist::AnalyseURL( string UrlT )
{

string::size_type i1;

string Domain;
string Toplevel;
string Path;
char ExactPath;
char ExactDomain;

    if ((i1 = UrlT.find("/")) == string::npos )
    {
     Domain = UrlT.substr(0,i1);
     Path = UrlT.substr(i1, UrlT.size()-i1);
     //Check Path!!!
    } else {
     Domain = UrlT;
     Path = "";
     ExactPath = 'y';
    }

    if ((i1 = Domain.rfind(".")) == string::npos ) //IPs are not detected and last part is handled as toplevel-domain :-(
    {
      Toplevel = Domain.substr( i1, Domain.size()-i1-1);
      Domain = Domain.substr (0,i1);
      //Check Path!!!
    } else {
     if ( Domain != "*" )
     {
       LogFile::ErrorMessage ("Missing Toplevel Domain: %s\n", UrlT.c_str());
       return false;
     } else {
       Domain ="";
       ExactDomain = 'r';
     }

    }
   
return true;
}



char Whitelist::CheckItem ( string *ItemT )
{

char position;
string character;

character = ItemT->substr(0,1);

if( character == "*" ){
 ItemT->erase(0,1);
 position = 'r';
}

character = ItemT->substr(ItemT->size()-1,1);

if( character == "*" ){
 ItemT->erase(ItemT->size()-1,1);

 if ( position == 'r' ){
  position = 'b';
 } else {
  position = 'l';
 }
}

if (ItemT->find("*") != string::npos ){
LogFile::ErrorMessage ("Whitelist - To many wildcards in %s\n", ItemT->c_str());
position = 'i';
}

return position;

}


Whitelist::Whitelist(){
}
Whitelist::~Whitelist(){
}
