/***************************************************************************
                          params.cpp  -  description
                             -------------------
    begin                : So Feb 20 2005
    copyright            : (C) 2005 by Peter Sebald / Christian Hilgers
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

#include "params.h"

map <string,string> Params::params;

void Params::SetDefaults()
{
	char buf[7];
// Parameters set during config taken from default.h
	SetConfig("USER",USER);
	SetConfig("GROUP",GROUP);
	snprintf(buf,6,"%d",SERVERNUMBER);
	SetConfig("SERVERNUMBER",buf);
	snprintf(buf,6,"%d",PORT);
	SetConfig("PORT",buf);
	SetConfig("BIND_ADDRESS",BIND_ADDRESS);
	SetConfig("KEEPBACKBUFFER",KEEPBACKBUFFER);
 	SetConfig("TRICKLING",TRICKLING);
// Parameters only setable by havp.config (whereever it is)
#ifdef USEKASPERSKY
 	SetConfig("AVECLIENT","/usr/local/bin/aveclient");
 	SetConfig("AVESOCKET","/var/run/aveserver");
#endif
 	SetConfig("MAXSCANSIZE","0");
 	SetConfig("WHITELIST","/etc/havp/whitelist");
 	SetConfig("BLACKLIST","/etc/havp/blacklist");
	SetConfig("PIDFILE","/var/run/havp.pid");
	SetConfig("DAEMON","true");
	SetConfig("TRANSPARENT","false");
	SetConfig("LOG_OKS","true");
	SetConfig("ACCESSLOG","/var/log/havp/access.log");
	SetConfig("ERRORLOG","/var/log/havp/havp.log");
	SetConfig("DISPLAYINITIALMESSAGES","true");
	SetConfig("DBRELOAD","60");
	SetConfig("SCANTEMPFILE","/var/tmp/havp/havp-XXXXXX");
	SetConfig("TEMPLATEPATH","/etc/havp/templates/en");
}

void Params::ReadConfig(string file)
{
 typedef string::size_type ST;
 ST i2;
 string line;
 ifstream input(file.c_str());
 if(!input) cerr << "Can not open config file " << file << '\n';
 while(input) {
 	getline(input,line);
 	string start=line.substr(0,1);
	ST i1 = line.find_first_not_of(" \t");
 	if(start != "#" && i1 != line.npos ) {
 		i2 = line.find_last_of(" \t");		
		string key=line.substr(i1,i2-i1);
		string val=line.substr(i2+1,line.size()-i2-1);
 		Params::SetConfig(key,val);
 	}
 }
 input.close();
}
void Params::SetConfig(string param, string value)
{ 
	string::const_iterator i = param.begin();
 	string::size_type e = param.find_first_of(" \t");
	if(e == param.npos) {
		e = param.size();
	} else {
		param.erase(e,param.size());
	}
	string::size_type j=0;
	while( j < e ) { 
		param[j++] = toupper(*i++);
	}
	params[param]=value;	
}

int Params::GetConfigInt(string param)
{
	string value = params[param];
	return atoi(value.c_str());
}

bool Params::GetConfigBool(string param)
{
	string value = params[param];
	if( value == "true") {
		return true;
	} else {
		return false;
	}
}

string Params::GetConfigString(string param)
{
	string value = params[param];
	return value;
}

void Params::ShowConfig()
{
 params.erase("");
 cout << "# HAVP uses these configuration parameters:\n\n";
 typedef map<string,string>::const_iterator CI;
 for(CI p = params.begin(); p != params.end(); ++p)
	cout << p->first << "=" << p->second << '\n';
}

void Params::Usage()
{
 cout << "Usage: havp [Options] \n\n";
 cout << "HAVP Version " << VERSION << "\n\n";
 cout << "Possible options are:\n";
 cout << "--help | -h                         This pamphlet\n";
 cout << "--pid-file=FileName | -p Filename   Path to PID-File\n";
 cout << "--conf-file=FileName | -c Filename  Use this Config-File\n";
 cout << "--show-config | -s                  Show configuration HAVP is using\n";
}

bool Params::SetParams(int argvT, char* argcT[])
{
 char ch;
 bool showconf = false;
 string option,value;
 typedef string::size_type ST;

 SetDefaults();

 while(--argvT) {
	value = *++argcT;
	ST i1 = value.find_first_not_of("-");
//none GNU options
	if( i1 == 1 ) {
		option = value.substr(i1,1);
		strncpy(&ch,option.c_str(),1);
		switch ( ch ) {
			case 'c':
			case 'p':
				{
				--argvT;
				if( argvT == 0 ) {
					Usage();
					return false;
				}
				value = *++argcT;
				break;
				}
			case 's':
				showconf = true;
                                break;
			case 'h':
		default:
			{
			Usage();
			return false;
			}
		}
//GNU options
	} else if( i1 == 2 ) {
		ST i2 = value.find("=");
		if(i2 < value.npos) {
			option = value.substr(i1,i2-2);
			value = value.substr(i2+1,value.size());
		} else {
			option = value.substr(i1,value.size());
		}
	} else {
		Usage();
		return false;
	}
//do the job
	if( option == "help" ) {
		Usage();
		return false;
	} else if( option == "show-config") {
		showconf = true;
	} else if( option == "pid-file" || option == "p" ) {
		SetConfig("PIDFILE",value);
	} else if( option == "conf-file" || option == "c" ) {
		ReadConfig(value);
        } else if(showconf == true) {
                //Nothing to prefent Usage
	} else {
		Usage();
		return false;
	}
 }

if(showconf == true) {
 ShowConfig();
 return false;
}

 return true;
}
