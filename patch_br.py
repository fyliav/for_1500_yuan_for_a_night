import json
import idaapi
import idc
from ida_tools import get_text_segment_range


def is_address_in_text_segment(addr, text_range):
    if text_range is None:
        return False
    start_ea, end_ea = text_range
    return start_ea <= addr < end_ea


def patch_br_instructions(instructions):
    # text_range = get_text_segment_range()
    # if text_range is None:
    #     print("Aborting: No valid .text segment found")
    #     return
    text_range = (0xF3C8C, 0x1C597C)
    for inst in instructions:
        try:
            addr = int(inst['addr'])
            reg = inst['reg']
            real_addr = int(inst['real'])
        except Exception as e:
            continue

        if not real_addr:
            print(f"Skipping {hex(addr)}: real_addr is invalid")
            continue

        if not is_address_in_text_segment(addr, text_range):
            print(f"Error: Address {hex(addr)} is not in .text segment, skipping...")
            continue
        if not is_address_in_text_segment(real_addr, text_range):
            print(f"Error: Target address {hex(real_addr)} is not in .text segment, skipping...")
            continue

        offset = real_addr - addr
        if abs(offset) > 128 * 1024 * 1024:  # b指令最大跳转范围±128MB
            print(f"Jump at {hex(addr)} to {hex(real_addr)} is out of range for b instruction, skipping...")
            continue

        offset = (offset >> 2) & 0x3FFFFFF
        b_encoding = 0x14000000 | offset

        idc.patch_dword(addr, b_encoding)
        print(f"Patched {hex(addr)}: br {reg} -> b {hex(real_addr)}")

        idc.create_insn(addr)
        idaapi.auto_mark_range(addr, addr + 4, idaapi.AU_CODE)


try:
    instructions = json.load(open(r"D:\desktop\ollvm_python\br.json"))
    patch_br_instructions(instructions)
except Exception as e:
    print(f"Error loading instructions.json: {e}")
