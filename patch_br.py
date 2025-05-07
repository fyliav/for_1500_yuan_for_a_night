import json

import idaapi
import idc


def patch_br_instructions(instructions):
    for inst in instructions:
        addr = inst['addr']
        reg = inst['reg']
        real_addr = inst['real']
        if not real_addr:
            continue
        # 创建b指令（无条件分支）
        # ARM b指令编码：0x14000000 | ((offset >> 2) & 0x3FFFFFF)
        offset = real_addr - addr
        if abs(offset) > 128 * 1024 * 1024:  # b指令最大跳转范围±128MB
            print(f"Jump at {hex(addr)} to {hex(real_addr)} is out of range for b instruction, skipping...")
            continue

        # 计算b指令的偏移量（以字为单位）
        offset = (offset >> 2) & 0x3FFFFFF
        b_encoding = 0x14000000 | offset

        # 写入b指令
        idc.patch_dword(addr, b_encoding)
        print(f"Patched {hex(addr)}: br {reg} -> b {hex(real_addr)}")

        # 确保IDA更新分析
        idc.create_insn(addr)
        idaapi.auto_mark_range(addr, addr + 4, idaapi.AU_CODE)


# 输入数据
instructions = json.load(open("instructions.json"))
# 执行补丁
patch_br_instructions(instructions)
