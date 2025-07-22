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


def get_text_segment_range():
    seg = idaapi.get_segm_by_name(".text")
    if seg is None:
        print("Error: Could not find .text segment")
        return None
    return seg.start_ea, seg.end_ea


def get_function_symbol_at_offset(offset):
    if not idc.is_mapped(offset):
        return None
    func = idaapi.get_func(offset)
    if not func:
        return None
    func_name = idc.get_func_name(offset)
    if not func_name:
        return None
    demangled_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
    return demangled_name if demangled_name else func_name


def is_in_plt(address):
    seg = idaapi.getseg(address)
    if not seg:
        return False
    seg_name = idc.get_segm_name(seg.start_ea)
    return seg_name in [".plt", ".plt.got"]
