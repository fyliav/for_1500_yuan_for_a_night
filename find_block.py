import json
from collections import deque

import ida_funcs
import ida_ua
import idaapi
import idc


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


class BlockInfo:
    def __init__(self):
        self.blocks = None
        self.inNum = 0
        self.outNum = 0
        self.instCount = 0

    def __str__(self):
        return json.dumps({
            "inNum": self.inNum,
            "outNum": self.outNum,
            "blocks": self.blocks.start_ea,
            "instCount": self.getInstCount(),
        })

    def __repr__(self):
        return self.__str__()

    def getInstCount(self):
        return (self.blocks.end_ea - self.blocks.start_ea) / 4


def make_BlockInfo(block):
    result = BlockInfo()
    result.blocks = block
    result.inNum = len(list(block.preds()))
    result.outNum = len(list(block.succs()))
    return result


def get_all_blocks(func_ea):
    block = get_block_by_address(func_ea)
    stack = [block]
    viewed = []
    viewedEa = []
    while stack:
        item = stack.pop()
        if item.start_ea in viewedEa:
            continue
        viewed.append(make_BlockInfo(item))
        viewedEa.append(item.start_ea)
        stack.extend(item.succs())
    return viewed


def decode_inst(p):
    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn, p)
    return idc.print_insn_mnem(p).lower(), insn


def check_dispatcher_node(node):
    if node.inNum > 1:
        return True

    return False


def check_pre_node(node):
    if node.inNum == 0:
        return True
    return False


def check_return_node(node):
    if node.outNum == 0:
        return True
    return False


def check_fake_node(node):
    if node.outNum > 1:
        return True
    if node.getInstCount() == 1:
        return True
    if node.getInstCount() == 3:
        fname, finst = decode_inst(node.blocks.start_ea)
        sname, sinst = decode_inst(idc.next_head(node.blocks.start_ea))
        print(fname, sname)
        if fname == "mov" and sname == "b":
            return True

    return False


def check_real_node(node):
    if node.inNum == 1 and node.outNum == 1:
        return True
    return False


def find_loop_heads(func_ea):
    print("find_loop_heads")
    allBlocks = get_all_blocks(func_ea)
    allBlocks = sorted(allBlocks, key=lambda x: x.inNum, reverse=True)
    returnNode = []
    preNode = []
    dispatcherNode = []
    fakeNode = []
    realNode = []

    for item in allBlocks:
        if check_pre_node(item):
            preNode.append(item)
            continue

        if check_return_node(item):
            returnNode.append(item)
            continue

        if check_dispatcher_node(item):
            dispatcherNode.append(item)
            continue

        if check_fake_node(item):
            fakeNode.append(item)
            continue

        if check_real_node(item):
            realNode.append(item)
            continue

        print("unknow node", item)

    for addr in dispatcherNode:
        add_block_color(addr, 0x0000ff)
    for addr in fakeNode:
        add_block_color(addr, 0x00ff00)

    for addr in realNode:
        add_block_color(addr, 0xffffff)
    for addr in preNode:
        add_block_color(addr, 0xffffff)
    for addr in returnNode:
        add_block_color(addr, 0xffcc33)
    ida_funcs.reanalyze_function(idaapi.get_func(func_ea))


find_loop_heads(0x2062A8)


# find_loop_heads(0x01DEDDC)


def find_converge_addr(loop_head_addr):
    """查找汇聚块"""
    print("find_converge_addr")
    block = get_block_by_address(loop_head_addr)
    if not block:
        return None
    preds = block.preds()
    pred_list = list(preds)
    if len(pred_list) == 2:  # 标准 FLA
        for pred in pred_list:
            if len(list(pred.preds())) > 1:
                return pred.start_ea
    else:  # 非标准 FLA
        return loop_head_addr
    return None


def find_real_blocks(loop_head_addr, converge_addr):
    """提取真实块"""
    print("find_real_blocks")
    real_blocks = []
    loop_head_block = get_block_by_address(loop_head_addr)
    if not loop_head_block:
        return []
    loop_head_preds = list(loop_head_block.preds())
    loop_head_preds_addr = [pred.start_ea for pred in loop_head_preds]
    if loop_head_addr != converge_addr:  # 标准 FLA
        loop_head_preds_addr.remove(converge_addr)  # 序言块
        real_blocks.extend(loop_head_preds_addr)
    converge_block = get_block_by_address(converge_addr)
    if not converge_block:
        return real_blocks
    list_preds = list(converge_block.preds())
    for pred_block in list_preds:
        if pred_block.start_ea == loop_head_addr:
            continue
        end_ea = pred_block.end_ea
        last_ins_ea = idc.prev_head(end_ea)
        mnem = idc.print_insn_mnem(last_ins_ea)
        size = get_basic_block_size(pred_block)
        if size > 4 and "B." not in mnem:
            start_ea = pred_block.start_ea
            mnem = idc.print_insn_mnem(start_ea)
            if mnem == "CSEL":
                csel_preds = pred_block.preds()
                for csel_pred in csel_preds:
                    real_blocks.append(csel_pred.start_ea)
            else:
                real_blocks.append(pred_block.start_ea)
    return sorted(real_blocks)


def find_ret_block_addr(func_ea):
    print("find_ret_block_addr")
    """查找返回块"""
    blocks = idaapi.FlowChart(idaapi.get_func(func_ea))
    for block in blocks:
        succs = block.succs()
        succs_list = list(succs)
        end_ea = block.end_ea
        last_ins_ea = idc.prev_head(end_ea)
        mnem = idc.print_insn_mnem(last_ins_ea)
        if len(succs_list) == 0 and mnem == "RET":
            ori_ret_block = block
            while True:
                tmp_block = block.preds()
                pred_list = list(tmp_block)
                if len(pred_list) == 1:
                    block = pred_list[0]
                    if get_basic_block_size(block) == 4:
                        continue
                    else:
                        break
                else:
                    break
            return block.start_ea
    return None


def find_fake_blocks(func_ea, real_blocks, ret_addr):
    print("find_fake_blocks")
    """识别虚假块"""
    blocks = idaapi.FlowChart(idaapi.get_func(func_ea))
    fake_blocks = []
    real_blocks_set = set(real_blocks)
    if ret_addr:
        real_blocks_set.add(ret_addr)

    # 保留返回块的相关后继块（可能包含 RET）
    ret_related_blocks = []
    if ret_addr:
        queue = deque()
        ret_block = get_block_by_address(ret_addr)
        if ret_block:
            queue.append(ret_block)
            while queue:
                cur_block = queue.popleft()
                for succ in cur_block.succs():
                    if succ.start_ea not in real_blocks_set:
                        real_blocks_set.add(succ.start_ea)
                        ret_related_blocks.append(succ.start_ea)
                        queue.append(succ)

    for block in blocks:
        if block.start_ea not in real_blocks_set:
            fake_blocks.append(block.start_ea)

    return sorted(fake_blocks)


def analyze_and_color_blocks(func_ea):
    """提取所有块并标记颜色"""
    # 初始化结果
    loop_heads = find_loop_heads(func_ea)
    converge_blocks = []
    all_real_blocks = []
    ret_addr = find_ret_block_addr(func_ea)

    print(f"循环头: {[hex(addr) for addr in loop_heads]}")

    # 提取汇聚块和真实块
    for loop_head_addr in loop_heads:
        converge_addr = find_converge_addr(loop_head_addr)
        if converge_addr:
            converge_blocks.append(converge_addr)
            print(f"循环头 {hex(loop_head_addr)} 的汇聚块: {hex(converge_addr)}")

        real_blocks = find_real_blocks(loop_head_addr, converge_addr)
        all_real_blocks.extend(real_blocks)
        print(f"循环头 {hex(loop_head_addr)} 的真实块: {[hex(addr) for addr in real_blocks]}")

    if ret_addr:
        all_real_blocks.append(ret_addr)
        print(f"返回块: {hex(ret_addr)}")

    all_real_blocks = sorted(list(set(all_real_blocks)))  # 去重并排序
    print(f"所有真实块: {[hex(addr) for addr in all_real_blocks]}")

    # 提取虚假块
    fake_blocks = find_fake_blocks(func_ea, all_real_blocks, ret_addr)
    print(f"虚假块: {[hex(addr) for addr in fake_blocks]}")

    # 颜色标记
    for addr in all_real_blocks:
        add_block_color(addr, 0xffcc33)  # 真实块：黄色
    for addr in converge_blocks:
        add_block_color(addr, 0x00ff00)  # 汇聚块：绿色
    for addr in fake_blocks:
        add_block_color(addr, 0xff0000)  # 虚假块：红色
    if ret_addr:
        add_block_color(ret_addr, 0x0000ff)  # 返回块：蓝色

    # 刷新 IDA 控制流图
    ida_funcs.reanalyze_function(idaapi.get_func(func_ea))
    print("控制流图已刷新，块已着色")

    return all_real_blocks, converge_blocks, fake_blocks, ret_addr
