import idaapi
import idc
import idautils


def get_text_segment_range():
    """获取.text段的起始和结束地址"""
    seg = idaapi.get_segm_by_name(".text")
    if seg is None:
        print("Error: Could not find .text segment")
        return None
    return seg.start_ea, seg.end_ea


def is_address_valid(addr, text_range):
    """校验地址是否在.text段范围内"""
    if text_range is None:
        return False
    start_ea, end_ea = text_range
    return start_ea <= addr < end_ea


def read_qword(ea):
    """读取64位值"""
    return idc.get_qword(ea)


def read_dword(ea):
    """读取32位值"""
    return idc.get_wide_dword(ea)


def read_byte(ea):
    """读取8位值"""
    return idc.get_byte(ea)


def write_byte(ea, value):
    """写入8位值"""
    idc.patch_byte(ea, value & 0xFF)


def decrypt_code(off_C7640_addr, text_range):
    """
    模拟init_proc的解密逻辑
    参数：
        off_C7640_addr: off_C7640的地址（全局指针数组）
        text_range: .text段的范围 (start_ea, end_ea)
    """
    # 模拟dword_2066D4（静态分析假设未初始化）
    # if read_dword(idc.get_name_ea_simple("dword_2066D4")) != 0:
    #     print("dword_2066D4 already set, skipping decryption")
    #     return

    # 读取off_C7640（v0）
    v0 = off_C7640_addr
    # if not is_address_valid(v0, text_range):
    #     print(f"Invalid off_C7640 address: {hex(v0)}")
    #     return

    # 读取v1（dword_30 + off_C7640）
    v1 = read_dword(v0 + idc.get_name_ea_simple("dword_30"))
    if not v1:
        print("v1 is 0, no decryption needed")
        return

    # 读取v2（off_18 + off_C7640）
    v2 = read_qword(v0 + idc.get_name_ea_simple("off_18"))
    if not v2:
        print("v2 is 0, no decryption needed")
        return

    # 计算加密区域起始地址（v3 = off_C7640 + v1）
    v3 = v0 + v1
    if not is_address_valid(v3, text_range):
        print(f"Invalid encryption start address: {hex(v3)}")
        return

    # 读取v5（加密区域大小）
    v5 = read_qword(v0 + idc.get_name_ea_simple("off_18"))
    if not is_address_valid(v3 + v5 - 1, text_range):
        print(f"Invalid encryption end address: {hex(v3 + v5 - 1)}")
        return

    # 模拟mprotect（静态分析无需实际调用，假设权限已满足）
    page_size = 0x1000  # 假设页面大小为4KB（常见值）
    v7 = v3 & -page_size
    v8 = (v5 + page_size - 1) & -page_size
    v9 = v8  # 简化，忽略v6（动态计算的额外大小）

    # 解密逻辑
    print(f"Decrypting region: {hex(v3)} to {hex(v3 + v5)}")

    # 第一个字节解密
    first_byte_addr = v3 - 1
    if is_address_valid(first_byte_addr, text_range):
        first_byte = read_byte(first_byte_addr)
        first_key = (v1 & 0xFF) + (v2 & 0xFF)
        decrypted_byte = first_byte ^ first_key
        write_byte(first_byte_addr, decrypted_byte)
        print(f"Decrypted byte at {hex(first_byte_addr)}: {hex(first_byte)} -> {hex(decrypted_byte)}")
    else:
        print(f"Invalid first byte address: {hex(first_byte_addr)}")

    # 后续字节解密
    i = v5
    while i != 1:
        v11 = v3 + i
        v12 = read_byte(v3 + i - 1)  # 前一个字节
        v13 = read_byte(v3 + i - 2)  # 前前一个字节
        if is_address_valid(v11 - 2, text_range):
            decrypted_byte = v13 ^ v12
            write_byte(v11 - 2, decrypted_byte)
            print(f"Decrypted byte at {hex(v11 - 2)}: {hex(read_byte(v11 - 2) ^ v12)} -> {hex(decrypted_byte)}")
        else:
            print(f"Invalid address for decryption: {hex(v11 - 2)}")
        i -= 1

    # 模拟缓存清理（静态分析无需实际执行）
    print("Skipping cache flush (static analysis)")

    # 模拟mprotect恢复权限（静态分析无需实际调用）
    print(f"Assuming mprotect({hex(v7)}, {v9}, PROT_READ|PROT_EXEC) succeeded")

    # 更新IDA分析
    idaapi.auto_mark_range(v7, v7 + v9, idaapi.AU_CODE)
    for ea in range(v7, v7 + v9, 4):
        idc.create_insn(ea)
    print(f"Updated IDA analysis for {hex(v7)} to {hex(v7 + v9)}")


def main():
    """主函数，执行解密"""
    text_range = get_text_segment_range()
    if not text_range:
        return

    # 假设off_C7640的地址（需手动定位）
    off_C7640_addr = idc.get_name_ea_simple("off_C7640")
    if off_C7640_addr == idc.BADADDR:
        print("Error: Could not find off_C7640 address")
        return

    # 执行解密
    decrypt_code(off_C7640_addr, text_range)


if __name__ == "__main__":
    main()