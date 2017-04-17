# Sample Rootkit for Linux
## About
This is sample rootkit implementation for Linux. It is able to hide processes, files and grants root privileges. It also have stealth mode (enabled by default) that prevents it from detecting.

## Usage
Just compile module (included Makefile does this against current kernel) and load it. There will be hidden file in `/proc` called `rtkit`. It's not visible when listing content of proc directory.

Just `cat /proc/rtkit` to see available commands. You can use attached program to give orders or use `echo -n` (don't forget `-n`, there should be no tailing new line).

Examples:
``echo -n thf >> /proc/rtkit``
``./rtcmd.py hp1337``

To gain root you should give "My Pen Is Long" command (popculture reference, without spaces, small letters) and then fork some shell from writing process. rtcmd.py does that for you if second parameter is specified.
``tools/rtcmd.py mypenislong /bin/bash``

## Notes
This code should run on Linux version 2.6.29 and higher, since before that `lookup_address` symbol wasn't exported. Were tested against 3.1.0, 3.1.5 and 3.1.6 and is fully working (both x86 and x86\_64).

Paper describing details of implementation (in polish) is [available](http://issuu.com/ivyl/docs/rootkit).
## License
Dual licensed under BSD and GPL.

## Resources
http://stackoverflow.com/questions/2103315/linux-kernel-system-call-hooking-example

http://linux.die.net/lkmpg/

http://lwn.net/Kernel/LDD3/

## Authors
Ivyl and t3hknr.
