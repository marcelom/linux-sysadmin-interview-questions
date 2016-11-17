Linux System Administrator/DevOps Interview Questions
====================================================

A collection of linux sysadmin/devops interview questions. Feel free to contribute via pull requests, issues or email messages.


## <a name='toc'>Table of Contents</a>

  1. [Contributors](#contributors)
  1. [General Questions](#general)
  1. [Simple Linux Questions](#simple)
  1. [Medium Linux Questions](#medium)
  1. [Hard Linux Questions](#hard)
  1. [Expert Linux Questions](#expert)
  1. [Networking Questions](#network)
  1. [MySQL Questions](#mysql)
  1. [DevOps Questions](#devop)
  1. [Fun Questions](#fun)
  1. [Demo Time](#demo)
  1. [Other Great References](#references)


####[[⬆]](#toc) <a name='contributors'>Contributors:</a>

* [moregeek](https://github.com/moregeek)
* [typhonius](https://github.com/typhonius)
* [schumar](https://github.com/schumar)
* [negesti](https://github.com/negesti)
* peter
* [andreashappe](https://github.com/andreashappe)
* [quatrix](https://github.com/quatrix)
* [biyanisuraj](https://github.com/biyanisuraj)
* [pedroguima](https://github.com/pedroguima)
* Ben


####[[⬆]](#toc) <a name='general'>General Questions:</a>

* What did you learn yesterday/this week?
* Talk about your preferred development/administration environment. (OS, Editor, Browsers, Tools etc.)
* Tell me about the last major Linux project you finished.
* Tell me about the biggest mistake you've made in [some recent time period] and how you would do it differently today. What did you learn from this experience?
* Why we must choose you?
* What function does DNS play on a network?
* What is HTTP?
* What is an HTTP proxy and how does it work?
* Describe briefly how HTTPS works.
* What is SMTP? Give the basic scenario of how a mail message is delivered via SMTP.
* What is RAID? What is RAID0, RAID1, RAID5, RAID10?
* What is a level 0 backup? What is an incremental backup?
* Describe the general file system hierarchy of a Linux system.


####[[⬆]](#toc) <a name='simple'>Simple Linux Questions:</a>

* What is the name and the UID of the administrator user?
  root, 0
* How to list all files, including hidden ones, in a directory?
  ls -la
* What is the Unix/Linux command to remove a directory and its contents?
  rm -r
* Which command will show you free/used memory? Does free memory exist on Linux?
  free, top
* How to search for the string "my konfi is the best" in files of a directory recursively?
  * grep -r "my konfi is the best" /dir
  * find -type f /dir -exec grep "my konfi is the best" {} \;
* How to connect to a remote server or what is SSH?
  * insecurely, telnet
  * securely, ssh: ssh is Secure SHell. it is an advanced and encryted way of connecting to a remote server.
* How to get all environment variables and how can you use them?
  * export, printenv, env
  * echo $PATH 
* I get "command not found" when I run ```ifconfig -a```. What can be wrong?
  * not in path, usually in /sbin
* What happens if I type TAB-TAB?
  * in an empty line, nothing
  * in a partial line (for example "ab"), will print all commands that begin with "ab"
  * in the context of a command, for example ls tab-tab, auto completes with all the directories in the current dir.
* What command will show the available disk space on the Unix/Linux system?
  * df
* What commands do you know that can be used to check DNS records?
  * nslookup, dig
* What Unix/Linux commands will alter a files ownership, files permissions?
  * chown
  * chmod
* What does ```chmod +x FILENAME```do?
  * adds x to owner, group and others
* What does the permission 0750 on a file mean?
  * means the owner can read, write and execute, group can read and execute, others can do nothing
* What does the permission 0750 on a directory mean?
  * means the owner can read the file names, create/delete files and read metadata from files, 
* How to add a new system user without login permissions?
  * set the shell to /bin/false
* How to add/remove a group from a user?
  * usermod
* What is a bash alias?
  * command substitution, ex alias ll=ls -l
* How do you set the mail address of the root/a user?
  * modify the /etc/aliases
  * create a $HOME/.forward
* What does CTRL-c do?
  * sends SIGINT to foreground process
* What is in /etc/services?
  * list of ip network ports (tcp and UDP) and names
* How to redirect STDOUT and STDERR in bash? (> /dev/null 2>&1)
  * > /dev/null 2>&1
* What is the difference between UNIX and Linux.
* What is the difference between Telnet and SSH?
  * secure/encrypted. Telnet is more limited as well, as it basically just connects to a remote terminal. ssh is more advanced, as it allows port forwarding, connecting to processes, etc.
* Explain the three load averages and what do they indicate.
  * 1, 5, 15 minutes average.
  * In Linux it means the average number of processes ready to run, or waiting to run.
* Can you name a lower-case letter that is not a valid option for GNU ```ls```?
  * ls -e


####[[⬆]](#toc) <a name='medium'>Medium Linux Questions:</a>

* What do the following commands do and how would you use them?
 * ```tee```
   * sends output to file and terminal at smae time 
 * ```awk```
   * pattern processing language
 * ```tr```
   * translate
 * ```cut```
   * split lines into delimited fields
 * ```tac```
   * cats a file in reverse
 * ```curl```
   * Command line URL processor
 * ```wget```
   * Web Get, a web downloader
 * ```watch```
   * continually executes a command
 * ```head```
   * prints the begining lines of a file
 * ```tail```
   * prints the ending lines of a file
* What does an ```&``` after a command do?
  * send it to background 
* What does ```& disown``` after a command do?
  * sends to bg and removed the process from the list of managed processes by the shell
* What is a packet filter and how does it work?
  * a software that looks into portions of a packet and decided its fate based on rules.
* What is Virtual Memory?
  * A memory management technique using both hardware and software.
  * it maps virtual addresses used in a program into physical addresses.
  * memory space is perceived by a process as a large contiguous space (or a collection of contiguous sements)
  * address translation hardware in the cpu (MMU) automatically translates these addresses
  * software in the OS may further extend these capabilities to provide a virtual address space that exceeds the real capacity, allowing processes to reference more memory than is actually available
  * primary benefit is to free processes from managing their own memory in a shared space, increasing security
  * paged virtual memory:
    * /proc/vmstat
    * memory is divided in pages, stored in page tables
    * pages contain a flag to indicate if it is in real memory or not
    * If real, MMU translates them automatically
    * If not, a page-fault is generated and OS supervisor called to manage the page
    * OS Supervisor creates and manages page tables
    * Some pages need to be pinned (OS Supervidor itself, for example)
  * pages contain a recently accessed bit, which is cleared in a schedule (every so often the os runs and resets the bits). Any page least recently used is a potential candidate to be swapped out
  * Also, pages can also exist in disk (for example from a binary, or a mmaped file). The executer loads the code and data files as needed, thus avoiding loading all at once in memory. Dead code is actually never loaded.
* What is swap and what is it used for?
  * virtual memory in disk (see above)
* What is an A record, an NS record, a PTR record, a CNAME record, an MX record?
  * A: Adress record, maps name sto IP addresses
  * NS: Name Server record, Delegates a DNS zone to use the given authoritative name servers
  * PTR: Pointer record, like CNAME but processing stops and only the name is returned
  * CNAME: Canonincal name record, alias of one name to another. The DNS lookup will continue by retrying the lookup with the new name.
  * MX: Mail Exchange, list the MTA for the domain, with priorities
* Are there any other RRs and what are they used for?
  * yes, several: TXT, AAAA
* What is a Split-Horizon DNS?
  * When a DNS server replies differently based on the source of the query
* What is the sticky bit?
  * Is a special unix ACL. When set in a dir, it treats files so that only the owner, root or the dir owner can rename or delete the file/dir.
* What does the immutable bit do to a file?
  * prevents a file from being modified/deleted
* What is the difference between hardlinks and symlinks? What happens when you remove the source to a symlink/hardlink?
  * ...
* What is an inode and what fields are stored in an inode?
  * A data structure that represents a filesystem object. Contains: userid, groupid, size, mode, additional flags, timestamps, link count, pointer to disk blocks where file content is
* How to force/trigger a file system check on next reboot?
  * e2tunefs, or create an empty file /forcefsck
* What is SNMP and what is it used for?
  * Simple Network Management Protocol, network device management, MIBs
* What is a runlevel and how to get the current runlevel?
  * system state, defined by a single digit integer. /sbin/runlevel
* What is SSH port forwarding?
  * an encrypted connection between a source and destination. Can be Local or remote.
* What is the difference between local and remote port forwarding?
  * Local: a port in the ssh client is forwarded to the ssh server, then to a remote destination
  * remote: a port in the ssh server is forwarded to the ssh client and then to a remote location
* What are the steps to add a user to a system without using useradd/adduser?
  * ...
* What is MAJOR and MINOR numbers of special files?
  * MAJOR defines an index in the driver table. MINOR is an identifier to the driver.
* Describe the mknod command and when you'd use it.
  * use it to create special device files: you pass a device type (c or b), a MAJOR and MINOR number.
* Describe a scenario when you get a "filesystem is full" error, but 'df' shows there is free space.
  * Out of inodes
* Describe a scenario when deleting a file, but 'df' not showing the space being freed.
  * Other hard links to it, the file is open by a running process, etc...
* Describe how 'ps' works.
  * probably prints out the entries in the process table... not sure
* What happens to a child process that dies and has no parent process to wait for it and what’s bad about this?
  * Creates a zombie.
* Explain briefly each one of the process states.
  * D, uninterruptible sleep: sleep state that won't handle a signal right away. It will wake only as a result of a waited-upon resource becoming available or after a time-out occurs during that wait (if specified when put to sleep). It is mostly used by device drivers waiting for disk or network IO (input/output). When the process is sleeping uninterruptibly, signals accumulated during the sleep will be noticed when the process returns from the system call or trap. (https://en.wikipedia.org/wiki/Sleep_(system_call))
  * R, running, or in the run queue
  * S, sleeping (interruptible)
  * T, stopped
  * Z, zombie/defunct
* What is a signal?
  * A limited form of inter-process communication.
  * An asynchronous notification sent to a process (or thread within the same process) in order to notify it of an event that occurred.
  * When sent, the operating system interrupts the target process' normal flow of execution to deliver the signal. Execution can be interrupted during any non-atomic instruction. If the process has previously registered a signal handler, that routine is executed. Otherwise, the default signal handler is executed.
  * 2 signals cannot be handled, and always perform the default action: SIGKILL and SIGSTOP.
  * The sigprocmask() call can be used to block and unblock delivery of signals. Blocked signals are not delivered to the process until unblocked. Signals that cannot be ignored (SIGKILL and SIGSTOP) cannot be blocked.
* What is a system call?
  * A programmatic way in which a computer program requests a service from the kernel of the operating system it is executed on. This may include hardware-related services (for example, accessing a hard disk drive), creation and execution of new processes, and communication with integral kernel services such as process scheduling.
  * System calls provide an essential interface between a process and the operating system.
  * most modern processors involves a security model. For example, specifies multiple privilege levels under which software may be executed: a program is usually limited to its own address space so that it cannot access or modify other running programs or the operating system itself, and is usually prevented from directly manipulating hardware devices (e.g. the frame buffer or network devices).
  * However, many normal applications obviously need access to these components, so system calls are made available by the operating system to provide well defined, safe implementations for such operations. The operating system executes at the highest level of privilege, and allows applications to request services via system calls, which are often initiated via interrupts.
  * An interrupt automatically puts the CPU into some elevated privilege level, and then passes control to the kernel, which determines whether the calling program should be granted the requested service. If the service is granted, the kernel executes a specific set of instructions over which the calling program has no direct control, returns the privilege level to that of the calling program, and then returns control to the calling program.
  * System calls are not made directly by the user program, but via a library, that acts as an intermediary. Making these calls directly in the user program is complicated and may possibly require embedded code.
* What are interrupts?
  * a signal to the processor emitted by hardware or software indicating an event that needs immediate attention. An interrupt alerts the processor to a high-priority condition requiring the interruption of the current code the processor is executing. The processor responds by suspending its current activities, saving its state, and executing a function called an interrupt handler (or an interrupt service routine, ISR) to deal with the event. This interruption is temporary, and, after the interrupt handler finishes, the processor resumes normal activities. There are two types of interrupts:
    * hardware interrupts: used by devices to communicate that they require attention from the operating system.[2] Internally, hardware interrupts are implemented using electronic alerting signals that are sent to the processor from an external device, which is either a part of the computer itself, such as a disk controller, or an external peripheral. For example, pressing a key on the keyboard or moving the mouse triggers hardware interrupts.
    * software interrupts: caused either by an exceptional condition in the processor itself, or a special instruction in the instruction set which causes an interrupt when it is executed. The former is often called a trap or exception and is used for errors or events occurring during program execution that are exceptional enough that they cannot be handled within the program itself. For example, a divide-by-zero exception will be thrown if the processor's arithmetic logic unit is commanded to divide a number by zero.
* How to know which process listens on a specific port?
  * netstat -lnp
* What is a zombie process and what could be the cause of it?
  * ...
* You run a bash script and you want to see its output on your terminal and save it to a file at the same time. How could you do it?
  * tee it
* Explain what echo "1" > /proc/sys/net/ipv4/ip_forward does.
  * enables routing
* Describe briefly the steps you need to take in order to create and install a valid certificate for the site https://foo.example.com.
  * generate a csr, sign it, install the server key, signed cert and chained cert
* Can you have several HTTPS virtual hosts sharing the same IP?
  * Yes with SNI
  * SNI sends the connecting server name as part of the TLS negotiation phase, and the server can pick the correct certificate at that time, essentially allowing several HTTPS servers to use the same IP address.
* What is a wildcard certificate?
  * a cert that matches names based on a wildcard:  *.google.com
* Which Linux file types do you know?
  * file, directory, link, device b & c, socket, pipe 
* What is the difference between a process and a thread? And parent and child processes after a fork system call?
  * Linux uses a 1-1 threading model, with (to the kernel) no distinction between processes and threads -- everything is simply a runnable task.
    On Linux, the system call `clone` clones a task, with a configurable level of sharing. `fork()` calls `clone(least sharing)` and `pthread_create()` calls `clone(most sharing)`.
    `fork`ing costs a tiny bit more than `pthread_create`ing because of copying tables and creating COW mappings for memory.
* What is the difference between exec and fork?
  * fork creates a new process, exec replaces the current running process
  * fork creates a new process by cloning the current running process
  * exec replaces the current running process by overlaying the current running code
* What is "nohup" used for?
  * ignores SIGHUP and sends output to a file
* What is the difference between these two commands?
 * ```myvar=hello```
   * sets myvar for the current shell
 * ```export myvar=hello```
   * marks an environment variable to be exported to child-processes, so that the child inherits them.
* How many NTP servers would you configure in your local ntp.conf?
  * at least 2
* What does the column 'reach' mean in ```ntpq -p``` output?
  * DONT KNOW
* You need to upgrade kernel at 100-1000 servers, how you would do this?
  * Ansible!
* How can you get Host, Channel, ID, LUN of SCSI disk?
  * /proc/scsi
* How can you limit process memory usage?
  * linux cgroups, not familiar with it
* What is bash quick substitution/caret replace(^x^y)?
  * dont know
* Do you know of any alternative shells? If so, have you used any?
  * csh, but barely...
* What is a tarpipe (or, how would you go about copying everything, including hardlinks and special files, from one server to another)?

####[[⬆]](#toc) <a name='hard'>Hard Linux Questions:</a>

* What is a tunnel and how you can bypass a http proxy?
* What is the difference between IDS and IPS?
* What shortcuts do you use on a regular basis?
* What is the Linux Standard Base?
* What is an atomic operation?
  * atomic, linearizable, indivisible or uninterruptible if it appears to the rest of the system to occur instantaneously.
* Your freshly configured http server is not running after a restart, what can you do?
* What kind of keys are in ~/.ssh/authorized_keys and what it is this file used for?
  * contains public keys for public key authentication
* I've added my public ssh key into authorized_keys but I'm still getting a password prompt, what can be wrong?
  * from= (in the authorized_keys file) could be wrong
* Did you ever create RPM's, DEB's or solaris pkg's?
* What does ```:(){ :|:& };:``` do on your system?
* How do you catch a Linux signal on a script?
  * trap in bash
  * signal module in python
* Can you catch a SIGKILL?
  * no
* What's happening when the Linux kernel is starting the OOM killer and how does it choose which process to kill first?
  * selects the best = largest least essential process. All processes have an oom_score.
* Describe the linux boot process with as much detail as possible, starting from when the system is powered on and ending when you get a prompt.
  * BIOS phase: does initial setup of devices/system, then loads and executes the MBR of the boot device
    * In systems with UEFI, Boot Loader Phase can be skipped by going straight to the Kernel Phase. This is not common...
  * Boot Loader Phase: can consist of multiple phases (like in Grub's case). Usually loads a stage-1 Grub loader, wihch will read the config from the filesystem and present a menu and CLI. After that, will load a stage-2 loader
  * Kernel Phase:
    * Kernel Loading Phase: loads the compressed image file and any RAM disks (initrd) if available. The image is decompressed in high memory
    * Kenel Startup Phase: establishes memory management, and detects CPU features. Then executes a large number of initialization functions: sets up IRQ, further Memory Management, device driver initialization, mounts the initrd in read-only mode and starts init
  * init Phase: init gets everything running the way it should be. There are several different ones: upstart, sysV, runit, systemd, etc...
* What's a chroot jail?
  * way to isolate a process from the rest of the system. root processes can break the jail.
* When trying to umount a directory it says it's busy, how to find out which PID holds the directory?
  * lsof | grep dir
* What's LD_PRELOAD and when it's used?
  * instructs the dynamic linker to preload something. used for debugging programs
* You ran a binary and nothing happened. How would you debug this?
  * strace it, possibly track down file activity (open, read, write, close) and other system calls...
  * -c is also useful, because it breaks down the calls in the end with some useful stats.
* What are cgroups? Can you specify a scenario where you could use them?
  * ? (limits, accounts for, and isolates the resource usage (CPU, memory, disk I/O, network, etc.) of a collection of processes)

####[[⬆]](#toc) <a name='expert'>Expert Linux Questions:</a>

* A running process gets ```EAGAIN: Resource temporarily unavailable``` on reading a socket. How can you close this bad socket/file descriptor without killing the process?


####[[⬆]](#toc) <a name='network'>Networking Questions:</a>

* What is localhost and why would ```ping localhost``` fail?
  * localhost is just a name that is defined in the /etc/hosts file. It usually points to the loopback interface 127.0.0.1.
  * It can fail for several reasons: loopback not replying to ICMP pings, name resolving to a different IP, etc...
* What is the similarity between "ping" & "traceroute" ? How is traceroute able to find the hops.
  * ping uses ICMP echo replies and echo requests, to determine if a particular host is up
  * traceroute uses increasingly consecutive TTL'ed packets to determine the route to a particular destination. Once the TTL is reached, an ICMP TIME EXCEEDED packet is sent back, and the route can be determined. The packets can be sent as ICMP or event TCP/UDP packets. By default, traceroute sends UDP packets to a random port in the destination. It knows when it is done because the last packet will return a ICMP PORT UNREACHABLE message. 
* What is the command used to show all open ports and/or socket connections on a machine?
* Is 300.168.0.123 a valid IPv4 address?
* Which IP ranges/subnets are "private" or "non-routable" (RFC 1918)?
  * 10.0.0.0/8
  * 172.16.0.0/12
  * 192.168.0.0/16
* What is a VLAN?
* What is ARP and what is it used for?
* What is the difference between TCP and UDP?
* What is the purpose of a default gateway?
* What is command used to show the routing table on a Linux box?
* A TCP connection on a network can be uniquely defined by 4 things. What are those things?
* When a client running a web browser connects to a web server, what is the source port and what is the destination port of the connection?
* How do you add an IPv6 address to a specific interface?
* You have added an IPv4 and IPv6 address to interface eth0. A ping to the v4 address is working but a ping to the v6 address gives yout the response ```sendmsg: operation not permitted```. What could be wrong?
* What is SNAT and when should it be used?
* Explain how could you ssh login into a Linux system that DROPs all new incoming packets using a SSH tunnel.
* How do you stop a DDoS attack?
* How can you see content of an ip packet?
* What is IPoAC (RFC 1149)?
* TCP stuff:
  * handshake: SYN, SYN-ACK, ACK
  * sliding window: 
  * maximum segment size (MSS): largest amount of data, specified in bytes, that TCP is willing to receive in a single segment.
  * teardown: four way FIN-ACK
* What is a router?
* Talk about subnet masks...
* Describe how NAT works.

####[[⬆]](#toc) <a name='mysql'>MySQL questions:</a>

* How do you create a user?
* How do you provide privileges to a user?
* What is the difference between a "left" and a "right" join?
* Explain briefly the differences between InnoDB and MyISAM.
* Describe briefly the steps you need to follow in order to create a simple master/slave cluster.
* Why should you run "mysql_secure_installation" after installing MySQL?
* How do you check which jobs are running?


####[[⬆]](#toc) <a name='devop'>DevOps Questions:</a>

* Can you describe your workflow when you create a script?
* What is GIT?
* What is a dynamically/statically linked file?
* What does "./configure && make && make install" do?
* What is puppet/chef/ansible used for?
* What is Nagios/Zenoss/NewRelic used for?
* What is the difference between Containers and VMs?
* How do you create a new postgres user?
* What is a virtual IP address? What is a cluster?
* How do you print all strings of printable characters present in a file?
* How do you find shared library dependencies?
* What is Automake and Autoconf?
* ./configure shows an error that libfoobar is missing on your system, how could you fix this, what could be wrong?
* What are the advantages/disadvantages of script vs compiled program?
* What's the relationship between continuous delivery and DevOps?
* What are the important aspects of a system of continuous integration and deployment?

####[[⬆]](#toc) <a name='fun'>Fun Questions:</a>

* A careless sysadmin executes the following command: ```chmod 444 /bin/chmod ``` - what do you do to fix this?
* I've lost my root password, what can I do?
* I've rebooted a remote server but after 10 minutes I'm still not able to ssh into it, what can be wrong?
* If you were stuck on a desert island with only 5 command-line utilities, which would you choose?
* You come across a random computer and it appears to be a command console for the universe. What is the first thing you type?
* Tell me about a creative way that you've used SSH?
* You have deleted by error a running script, what could you do to restore it?
* What will happen on 19 January 2038?


####[[⬆]](#toc) <a name='demo'>Demo Time:</a>

* Unpack test.tar.gz without man pages or google.
* Remove all "*.pyc" files from testdir recursively?
* Search for "my konfu is the best" in all *.py files.
* Replace the occurrence of "my konfu is the best" with "I'm a linux jedi master" in all *.txt files.
* Test if port 443 on a machine with IP address X.X.X.X is reachable.
* Get http://myinternal.webserver.local/test.html via telnet.
* How to send an email without a mail client, just on the command line?
* Write a ```get_prim``` method in python/perl/bash/pseudo.
* Find all files which have been accessed within the last 30 days.
* Explain the following command ```(date ; ps -ef | awk '{print $1}' | sort | uniq | wc -l ) >> Activity.log```
* Write a script to list all the differences between two directories.
* In a log file with contents as ```<TIME> : [MESSAGE] : [ERROR_NO] - Human readable text``` display summary/count of specific error numbers that occurred every hour or a specific hour.


####[[⬆]](#toc) <a name='references'>Other Great References:</a>

Some questions are 'borrowed' from other great references like:

* https://github.com/darcyclarke/Front-end-Developer-Interview-Questions
* https://github.com/kylejohnson/linux-sysadmin-interview-questions/blob/master/test.md
* http://slideshare.net/kavyasri790693/linux-admin-interview-questions
