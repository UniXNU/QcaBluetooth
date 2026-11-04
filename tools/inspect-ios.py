#!/usr/bin/env python3
"""Inspect a local bluetoothd image and locate native transport/model call sites."""
import argparse,bisect,hashlib,json,struct,uuid
from pathlib import Path

class Image:
    def __init__(self,path):
        self.data=Path(path).read_bytes();d=self.data
        if d[:4]!=b'\xcf\xfa\xed\xfe':raise ValueError('requires a thin 64-bit Mach-O')
        _,self.cpu,self.subtype,_,count,_,_,_=struct.unpack_from('<8I',d)
        self.segments=[];self.sections=[];self.functions=[];self.uuid=None;at=32;starts=None
        for _ in range(count):
            cmd,size=struct.unpack_from('<II',d,at)
            if size<8 or at+size>len(d):raise ValueError('invalid load command')
            if cmd==0x19:
                name,va,vs,off,fs,_,_,n,_=struct.unpack_from('<16sQQQQIIII',d,at+8)
                self.segments.append((name.rstrip(b'\0').decode(),va,vs,off,fs))
                for i in range(n):
                    sname,seg,addr,nbytes,offset=struct.unpack_from('<16s16sQQI',d,at+72+i*80)
                    self.sections.append(dict(name=sname.rstrip(b'\0').decode(),segment=seg.rstrip(b'\0').decode(),address=addr,size=nbytes,offset=offset))
            elif cmd==0x1b:self.uuid=str(uuid.UUID(bytes=d[at+8:at+24])).upper()
            elif cmd==0x26:starts=struct.unpack_from('<II',d,at+8)
            at+=size
        self.base=next(v for name,v,_,_,_ in self.segments if name=='__TEXT')
        if starts:
            at,end=starts[0],sum(starts);address=self.base
            while at<end:
                delta=shift=0
                while at<end:
                    b=d[at];at+=1;delta|=(b&127)<<shift;shift+=7
                    if not b&128:break
                if not delta:break
                address+=delta;self.functions.append(address)
    def address(self,offset):
        for _,va,_,off,size in self.segments:
            if off<=offset<off+size:return va+offset-off
        return None
    def function(self,address):
        i=bisect.bisect_right(self.functions,address)-1
        if i<0:return None
        return [hex(self.functions[i]),hex(self.functions[i+1]) if i+1<len(self.functions) else None]
    def inspect(self):
        terms=['com.apple.uart.sk.bluetooth','transport-encoding','transport-speed','THIRD_PARTY_DONGLE',
               'Invalid chipset %d','RunBuiltinScript','com.apple.BlueTool','initCmdReadLeLocalSupportedFeaturesCB',
               'BCM_4357','SupportsMultipleAdvertising','initCoreStack']
        targets={};strings={};d=self.data
        for term in terms:
            raw=term.encode()+b'\0';at=0;strings[term]=[]
            while (at:=d.find(raw,at))>=0:
                va=self.address(at)
                if va is not None:strings[term].append(hex(va));targets.setdefault(va,[]).append(term)
                at+=len(raw)
        for s in self.sections:
            if s['name']!='__cfstring':continue
            for at in range(s['offset'],s['offset']+s['size']-31,32):
                ptr=struct.unpack_from('<Q',d,at+16)[0]
                for candidate in [ptr,ptr&0xffffffffff,self.base+(ptr&0xffffffff)]:
                    if candidate in targets:
                        va=self.address(at);targets.setdefault(va,[]).extend(targets[candidate]);break
        refs=[]
        for s in self.sections:
            if s['name']!='__text':continue
            code=memoryview(d)[s['offset']:s['offset']+s['size']]
            for off in range(0,len(code)-20,4):
                ins=struct.unpack_from('<I',code,off)[0]
                if ins&0x9f000000!=0x90000000:continue
                imm=((ins>>29)&3)|((ins>>5)&0x7ffff)<<2
                if imm&(1<<20):imm-=1<<21
                pc=s['address']+off;page=(pc&~4095)+(imm<<12);reg=ins&31
                for delta in range(4,20,4):
                    nxt=struct.unpack_from('<I',code,off+delta)[0]
                    if nxt&0xff000000!=0x91000000 or (nxt>>5)&31!=reg:continue
                    target=page+(((nxt>>10)&0xfff)<<(12 if nxt&(1<<22) else 0))
                    if target in targets:refs.append(dict(at=hex(pc+delta),target=hex(target),terms=targets[target],function=self.function(pc)))
        return dict(sha256=hashlib.sha256(d).hexdigest(),uuid=self.uuid,cpu=self.cpu,subtype=hex(self.subtype),
                    strings=strings,references=refs,function_count=len(self.functions))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('image',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    report=Image(a.image).inspect();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
