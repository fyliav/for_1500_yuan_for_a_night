import json

import ida_ua
import idaapi
import idc
import idautils


def get_block_by_address(ea):
    """获取指定地址的基本块"""
    func = idaapi.get_func(ea)
    if not func:
        return None
    blocks = idaapi.FlowChart(func)
    for block in blocks:
        if block.start_ea <= ea < block.end_ea:
            return block
    return None


def get_basic_block_size(bb):
    """计算基本块大小（字节）"""
    return bb.end_ea - bb.start_ea


def add_block_color(node, color):
    curr_addr = node.blocks.start_ea
    while curr_addr < node.blocks.end_ea:
        idc.set_color(curr_addr, idc.CIC_ITEM, color)
        curr_addr = idc.next_head(curr_addr)


def get_all_blocks(func_ea):
    block = get_block_by_address(func_ea)
    stack = [block]
    viewed = []
    viewedEa = []
    while stack:
        item = stack.pop()
        if item.start_ea in viewedEa:
            continue
        viewed.append(item)
        viewedEa.append(item.start_ea)
        stack.extend(item.succs())
    return viewed


def decode_inst(p):
    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn, p)
    return idc.print_insn_mnem(p).lower(), insn


decryption_ops = ['EOR', 'AND', 'ORR', 'BIC', 'ORN', 'MVN', 'SUB', 'LSL']


def find_decryption_block(func_addr):
    blocks = get_all_blocks(func_addr)
    for block in blocks:
        _


# for func_ea in idautils.Functions():
#     find_decryption_block(func_ea)

print(idc.get_operand_value(0x0481B00, 0))
