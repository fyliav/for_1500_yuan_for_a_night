from collections import deque


# import idaapi
# import idc


# def get_function_symbol_at_offset(offset):
#     if not idc.is_mapped(offset):
#         return None
#     func = idaapi.get_func(offset)
#     if not func:
#         return None
#     func_name = idc.get_func_name(offset)
#     if not func_name:
#         return None
#     demangled_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
#     return demangled_name if demangled_name else func_name
#
#
# def is_in_plt(address):
#     seg = idaapi.getseg(address)
#     if not seg:
#         return False
#     seg_name = idc.get_segm_name(seg.start_ea)
#     return seg_name in [".plt", ".plt.got"]


class CallInfo:
    def __init__(self):
        self.type = None
        self.depth = None
        self.fromModuleName = None
        self.fromSymbolName = None
        self.toModuleName = None
        self.toSymbolName = None
        self.fromOffset = None
        self.toOffset = None
        self.fromAddr = None
        self.toAddr = None
        self.jumpOut = None
        self.fromIdaSymbolName = None
        self.toIdaSymbolName = None
        self.isPlt = False


def load_trace(path):
    result = []
    data = open(path).read()
    lines = data.split("\n")
    for line in lines:
        if not line.startswith("call") and not line.startswith("ret"):
            continue
        info = CallInfo()
        sp = line.split(":")
        if sp[0] == "call":
            info.type = "call"
            info.jumpOut = sp[1]
            info.depth = int(sp[2])  # 原始深度
            info.fromModuleName = sp[3]
            info.fromSymbolName = sp[4]
            info.fromAddr = int(sp[5], 16)
            info.fromOffset = int(sp[6], 16)
            info.toModuleName = sp[7]
            info.toSymbolName = sp[8]
            info.toAddr = int(sp[9], 16)
            info.toOffset = int(sp[10], 16)
        else:
            info.type = "ret"
            info.depth = int(sp[1])
            info.fromModuleName = sp[2]
            info.fromSymbolName = sp[3]
            info.fromAddr = int(sp[4], 16)
            info.fromOffset = int(sp[5], 16)
            info.toModuleName = sp[6]
            info.toSymbolName = sp[7]
            info.toAddr = int(sp[8], 16)
            info.toOffset = int(sp[9], 16)
        result.append(info)
    return result


def make_call_trace(data: list[CallInfo]):
    # 为每个 call/ret 获取 IDA 符号名并标记 PLT
    # for item in data:
    #     if item.type == "call":
    #         item.fromIdaSymbolName = get_function_symbol_at_offset(item.fromOffset)
    #         item.toIdaSymbolName = get_function_symbol_at_offset(item.toOffset)
    #         item.isPlt = is_in_plt(item.toAddr)


    call_stack = deque()
    corrected_data = []
    current_depth = 0

    for item in data:
        if item.type == "call":
            call_stack.append((item.fromAddr, item.toAddr, current_depth))
            item.depth = current_depth
            current_depth += 1
            corrected_data.append(item)
            # 如果是 PLT 调用（外部函数），假设无 ret，立即减少深度
            if item.isPlt:
                current_depth -= 1
                call_stack.pop()  # 移除 PLT 调用
        elif item.type == "ret":
            # 查找匹配的 call（ret 的 toAddr 应匹配 call 的 toAddr）
            while call_stack:
                last_call = call_stack[-1]
                if last_call[1] == item.toAddr:  # 匹配 call 的目标地址
                    item.depth = last_call[2]
                    call_stack.pop()
                    current_depth = last_call[2]
                    corrected_data.append(item)
                    break
                else:
                    call_stack.pop()
                    current_depth -= 1
            else:
                item.depth = current_depth
                corrected_data.append(item)

    # 按深度缩进输出
    for item in corrected_data:
        indent = "  " * item.depth
        if item.type == "call":
            symbol_info = f"{item.toIdaSymbolName or item.toSymbolName or 'Unknown'}@0x{item.fromOffset:x}@0x{item.toOffset:x}"
            if item.isPlt:
                symbol_info += " [PLT]"
            print(f"{indent}call: {symbol_info}")
        else:
            symbol_info = f"{item.toIdaSymbolName or item.toSymbolName or 'Unknown'}@0x{item.toOffset:x}"
            print(f"{indent}ret: {symbol_info}")


make_call_trace(load_trace(r"D:\desktop\ollvm\360\log\trace_3358_619128571"))
