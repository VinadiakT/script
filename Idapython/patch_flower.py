from ida_bytes import get_bytes, patch_bytes
import re
addr = 0
end = 0x1100
# buf = "".join(["%02x"%ord(i) for i in get_bytes(addr,end-addr)])
buf = get_bytes(addr, end-addr)

def handler1(s):
    s = s.group(0)
    s = b"\x90"*len(s)
    return s

pattern1 = rb"\xE8\x00\x00\x00\x00\x48\x83\x04\x24\x06\xC3"
buf = re.sub(pattern1, handler1, buf, flags=re.I)
# buf = "".join([chr(int(buf[2*i]+buf[2*i+1], 16)) for i in range(len(buf)//2) ])
print(hex(addr))
patch_bytes(addr, buf)
print("Done")
