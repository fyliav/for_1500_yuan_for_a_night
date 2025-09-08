import ida_segment

import ida_search
import idautils
import idc
import idaapi


def patch_to_nop(addr, count):
    nop = b"\x1F\x20\x03\xD5"
    for i in range(count):
        idaapi.patch_bytes(addr + i * 4, nop)


def get_asm(addr):
    asm = idc.GetDisasm(addr)
    if asm == "":
        return ""
    return asm[:asm.find(" ")]


def is_valid_asm_instruction(address):
    return idc.is_code(idc.get_full_flags(address))


def find_large_not_code():
    text_seg = ida_segment.get_segm_by_name(".text")
    start_address = text_seg.start_ea
    end_address = text_seg.end_ea
    cur_addr = start_address
    lastNotCode = 0
    notCodeList = []
    while cur_addr < end_address:
        code = idc.GetDisasm(cur_addr)
        isCode = is_valid_asm_instruction(cur_addr)
        if not isCode and lastNotCode == 0:
            lastNotCode = cur_addr
        if isCode and lastNotCode != 0:
            info = {
                "start": lastNotCode,
                "len": cur_addr - lastNotCode
            }
            notCodeList.append(info)
            lastNotCode = 0
        cur_addr = idc.next_head(cur_addr)
    return notCodeList


notCode = find_large_not_code()
for item in notCode:
    print("start:" + hex(item["start"]) + ", len: " + str(item["len"]))
    patch_to_nop(item["start"], int(item["len"] / 4))
