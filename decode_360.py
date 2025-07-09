import idaapi
import idc
from ida_tools import get_text_segment_range


def decode():
    text_start, text_end = get_text_segment_range()
    v1 = 0x34b0
    v2 = 0x1c098
    v3 = v1

    idc.patch_byte(text_end - 1, idaapi.get_byte(text_end - 1) ^ (v1 + v2))
    i = 0x1C098
    while i != 1:
        v11 = (v3 + i)
        v12 = idaapi.get_byte(v3 + i - 1)
        v13 = idaapi.get_byte(v3 + i - 2)
        i -= 1
        idc.patch_byte(v11 - 2, v13 ^ v12)


decode()
