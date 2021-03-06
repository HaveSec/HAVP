# HAVP - HTTP Antivirus Proxy

![HAVP-Logo](http://www.havp.org/wp-content/uploads/2020/10/HAVP.png)

## Short Description
HAVP (HTTP Antivirus Proxy) is a HTTP proxy with an antivirus scanner. It supports the free ClamAV , but also commercial solutions e.g. Kaspersky, Sophos and F-Prot. The main aims are continuous, non-blocking downloads and smooth scanning of HTTP traffic. Havp antivirus proxy has a parent and transparent proxy mode. It can be used with squid or standalone

Further information can be found at
<http://havp.org>

## UPGRADING

Just install HAVP normally. Your config will be preserved, but check
havp.config for possible new options. Templates are overwritten, so if
you have your own, make sure it is not in any default directory.


## BASIC INSTALLATION

HAVP has been tested only with GCC.
Other compilers like Sun Studio have some problems currently.

Installation:

```
   ./configure    (if you don't want /usr/local, use --prefix=/other/path)
   make
   make install
```

You can use the following path options in configure:

```
  --prefix         base directory, default "/usr/local"
  --sbindir        location of havp-binary, default "$prefix/sbin"
  --sysconfdir     location of etc, default "$prefix/etc" (+ /havp)
  --localstatedir  location of pidfile, default "/var" (+ /run/havp)
```

  Also `make install DESTDIR=/tmp/havp` is supported for helping
  in creating packages etc.

It is recommended to create a havp user:

```
  # groupadd havp 
  # useradd -g havp havp
```

Check the configfile: `/usr/local/etc/havp/havp.config`

If Linux is used, you need to enable mandatory locking for the partition
where your tempfiles are located. Solaris supports mandatory locking
without these extra steps:

  The default location for logfiles is `/var/spool/havp`
  Don't use mandatory locking for `/`

  Using tmpfs might have some problems, make sure you test it properly.
  Add mand-option to `/etc/fstab` so it will stay after reboot e.g:
  
  `echo "none /var/spool/havp tmpfs mand,nodev,nosuid,noexec,nodiratime,size=50M 0 0" >> /etc/fstab`

  NOTE: Mandatory locking could make it possible for evil local accounts
  to hang the system. You should run HAVP anyway on non-public server.

Make sure the directories you are using have correct permissions:

```
  # chown havp /var/spool/havp /var/log/havp /var/run/havp
  # chmod 700 /var/spool/havp /var/log/havp /var/run/havp
```
Start havp:
```
  # /usr/local/sbin/havp -c /path/to/config
```
You can also install rc-script to your system from sources etc/init.d.

If you have problems check the logfiles:
```
  /var/log/havp/havp.log
  /var/log/havp/access.log
```
More information and help can be found at HAVP forum: http://havp.hege.li/



## OS SPECIFIC INSTRUCTIONS

Linux:
------

Use GCC 3.4+.

Solaris 9:
----------

You may need lots of swap space if you use library scanners (ClamAV and
Trophie). It wants to reserve it even when it is not really used. If there
is not enough, you will get fork errors. Worst case formula: (20MB *
USEDLIBRARYSCANNERS) * (USEDSCANNERS + 1) * SERVERNUMBER.

GCC 3.4.2 from sunfreeware.com is recommended.

You may need to fix GCC headers like this:
```
  # cd /usr/local/libexec/gcc/*/3.4.2/install-tools
  # ./mkheaders
```
Solaris 10:
-----------

Swap space is not an issue anymore.

Use GCC 3.4.x that comes bundled at `usr/sfw/bin/gcc`.
It is installed from SUNWgcc package.

FreeBSD:
--------

Use GCC 3.4+ from ports. FreeBSD does not support mandatory locking, which
means KEEPBACK settings can not be used (only TRICKLING is supported). This
means everything is first downloaded fully and only then sent to client.

You need to use `--disable-locking` option to compile.



## SCANNER SPECIFIC INSTRUCTIONS

ClamAV 
------

Library is used directly, so there is no need for clamd running.

If you choose to use clamd (which is not recommended as library support has
less overhead), you need to enable AllowSupplementaryGroups in clamd.conf,
and add clamav user to havp group.



####== NOTICE: ==
You must check your antivirus license before using HAVP with commercial
scanners. Usage might not be allowed. We do not give any warranty!


Kaspersky 
---------

Tested with aveserver daemon found in Linux File Server and Linux Mail
Server package.

You should set ReportLevel=1 at [aveserver.report] section, so log will not
fill disk.


Trend Micro (Trophie)
---------------------

/etc/iscan must point to the directory where libvsapi.so and
virus patterns are located. Create link if necessary.

Trend library is used directly, so daemon is not required to be running.
You should naturally run some pattern update script, if Trend itself is
not running.


AVG 
---

Recommended changes to avg.conf (version 7.5): 
```
 [AvgCommon] 

 heuristicAnalysis = 1 
 processesArchives = 1 

 [AvgDaemon] 

 # Raise number of daemons atleast equal to SERVERNUMBER/MAXSERVERS
 numOfDaemons = xx 
```

F-Prot 
------

Supported.


NOD32
-----

Tested with Linux Mail Server and Linux File Server packages.
File Server version can not display virus names.

For version 3.0+, see settings in /etc/esets/esets.cfg (num_thrd etc). Also
you want to disable syslogging.


Sophos (Sophie)
---------------

You need to make sure Sophie is working first, you can get it from:
http://www.clanfield.info/sophie/

Change user or group to havp user in sophie.cfg, so it can read tempfiles.
Also change maxproc value to atleast SERVERNUMBER/MAXSERVERS value!


Avast!
------

Linux/Unix Servers version is required.

Recommended changes to avastd.conf:
```
 # Raise number to atleast equal of SERVERNUMBER
 daemoncount = XX
 # Raise number to atleast equal of MAXSERVERS
 maxdaemoncount = XX
 archivetype = A
 testall = 1
 testfull = 0
```

Arcavir
-------

Start arcavird with enough processes, like "arcavird 16".


DrWeb
-----

Recommended changes to drweb32.ini: 
```
; Raise number to atleast equal of SERVERNUMBER 
MaxChildren = xx 
PreFork = Yes
```

