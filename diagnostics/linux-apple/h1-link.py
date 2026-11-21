"""Disposable point-to-point IPv4 link to QEMU's second Ethernet card."""
import ctypes
import fcntl
import os
from pathlib import Path
import select
import socket
import struct
import subprocess

local=socket.inet_aton('192.0.2.1')
remote=socket.inet_aton('192.0.2.2')
mac=bytes.fromhex('525400112233')
guest=bytes.fromhex('525400112234')
tun=socket.socket(32,socket.SOCK_DGRAM,2)
info=fcntl.ioctl(tun.fileno(),0xc0644e03,struct.pack('=I96s',0,b'com.apple.net.utun_control'))
addr=struct.pack('=BBHII5I',32,32,2,struct.unpack_from('=I',info)[0],0,0,0,0,0,0)
libc=ctypes.CDLL(None,use_errno=True)
if libc.connect(tun.fileno(),addr,len(addr))!=0:raise OSError(ctypes.get_errno(),'utun connect')
name=tun.getsockopt(2,2,64).rstrip(b'\0').decode()
subprocess.run(['/sbin/ifconfig',name,'inet','192.0.2.1','192.0.2.2','mtu','1500','up'],check=True)
link=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
link.bind(('127.0.0.1',11080))
link.connect(('127.0.0.1',11081))
print('Isolated IP link up',name,flush=True)
while True:
    ready,_,_=select.select([link,tun],[],[],10)
    for s in ready:
        try: pkt=s.recv(65535)
        except ConnectionRefusedError: continue
        if s is tun:
            if pkt[:4]!=struct.pack('!I',socket.AF_INET) or pkt[16:24]!=local+remote:continue
            try:link.send(guest+mac+b'\x08\x00'+pkt[4:])
            except ConnectionRefusedError:pass
        elif pkt[6:12]==guest:
            if pkt[12:14]==b'\x08\x00' and pkt[26:34]==remote+local:
                tun.send(struct.pack('!I',socket.AF_INET)+pkt[14:])
            elif pkt[12:14]==b'\x08\x06' and pkt[20:22]==b'\0\x01' and pkt[38:42]==local:
                link.send(guest+mac+b'\x08\x06'+pkt[14:20]+b'\0\x02'+mac+local+guest+remote)
