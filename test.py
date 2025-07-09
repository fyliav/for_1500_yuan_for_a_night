import idaapi
import idautils
import idc
import keystone

#初始化Ks
ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)

def getPredBlockIndex(block):

    preds_list = list(block.preds())
    preds_len = len(preds_list)
    if preds_len > 1:
        print(hex(block.start_ea), " 前驱数量-->", preds_len)
        return None
    elif preds_len == 0:
        print(hex(block.start_ea)," 没有前驱块")
        return None

    pred = preds_list[0]
    end_addr = pred.end_ea
    last_ins_ea = idc.prev_head(end_addr)
    mnem = idc.print_insn_mnem(last_ins_ea)
    # print(mnem,"-->",hex(pred.start_ea))

    if mnem == 'B.EQ' or mnem == "B.NE":
        CMP_ea = idc.prev_head(last_ins_ea)
        mnem = idc.print_insn_mnem(CMP_ea)
        CMP_1 = idc.print_operand(CMP_ea,1)

        if mnem == 'CMP':
            MOV_ea = idc.prev_head(CMP_ea)
            mnem = idc.print_insn_mnem(MOV_ea)
            if mnem == 'MOV':
                index = idc.get_operand_value(MOV_ea, 1)
                return hex(index)
            else:
                if CMP_1 == "W26":
                    return hex(0xA9D4543B)
                elif CMP_1 == "W24":
                    return hex(0xE4DBC33F)
    return None

def findLoopEntryBlockAllPreds(loop_end_ea):
    block = getBlockByAddress(loop_end_ea)
    for pred in block.preds():
        ea = idc.prev_head(pred.end_ea)
        print("主分发器前驱基本块:", hex(ea), idc.GetDisasm(ea))

def getBlockLink(func_ea,loop_end_ea):
    state_map = {}  #用于记录真实块
    func = idaapi.get_func(func_ea)
    blocks = idaapi.FlowChart(func) #获取方法中所有的基本块

    # findLoopEntryBlockAllPreds(loop_end_ea)#获取主分发器的所有前驱块

    for block in blocks:
        block_start_ea = block.start_ea  #基本块起始地址
        block_end_ea = block.end_ea #基本块结束地址
        next_states = []    #记录后继真实块的索引

        if block_start_ea == 0x43058: #添加序言块
            next_states.append(hex(0x665797A5))
            next_states.append(None)
            state_map[hex(block_start_ea)] = next_states
            continue

        last_ins_addr = idc.prev_head(block_end_ea)#获取传入地址的上一条地址
        mnem = idc.print_insn_mnem(last_ins_addr)  #获取指令的操作符
        op_0 = idc.get_operand_value(last_ins_addr, 0) #获取指令的操作数的第0位

        #以下是遍历特征向state_map里添加所有的真实块
        if  mnem == "B" and op_0 == loop_end_ea:
            ins = idc.prev_head(last_ins_addr)
            mnem = idc.print_insn_mnem(ins)

            if mnem == "MOV":
                mov_1 = idc.get_operand_value(ins,1)
                next_states.append(hex(mov_1))

                pred_index = getPredBlockIndex(block)
                next_states.append(pred_index)
            if mnem == "MOVK":
                #MOVK            W9, #0x4E30,LSL#16
                MOVK_0 = idc.print_operand(ins, 0)
                MOVK_1 = idc.get_operand_value(ins,1)
                mov_0 = ""
                mov_1 = 0
                for ea in idautils.Heads(block_start_ea, block_end_ea):#获取指定地址段的汇编指令
                    mnem = idc.print_insn_mnem(ea)
                    if mnem == "MOV":
                        mov_0 = idc.print_operand(ea,0)
                        if MOVK_0 == mov_0:
                            mov_1 = idc.get_operand_value(ea,1)
                            break

                if MOVK_0 == mov_0:
                    #MOV W8,  # 0xF5EA
                    #MOVK            W8, #0x89EF,LSL#16
                    #结果为 w8 = 0x89EFF5EA
                    if  idc.GetDisasm(ins).find("LSL#16") != -1:
                       index = (MOVK_1 << 16) | mov_1
                       next_states.append(hex(index))

                       pred_index = getPredBlockIndex(block)
                       next_states.append(pred_index)

                    else:
                        print("未匹配算术移位:",hex(block_start_ea))
            if mnem == "CSEL":
                print("CSEL:",hex(block_start_ea))
                if block_start_ea == 0x43168:
                    next_states.append(hex(0x4E30550D))
                    next_states.append(hex(0xBEE4A4C9))

                    pred_index = getPredBlockIndex(block)
                    next_states.append(pred_index)

                elif block_start_ea == 0x431d8:
                    next_states.append(hex(0xA9D4543B))
                    next_states.append(hex(0xC7AC1F5F))

                    pred_index = getPredBlockIndex(block)
                    next_states.append(pred_index)

                elif block_start_ea == 0x433d8:
                    next_states.append(hex(0xF5C370CA))
                    next_states.append(hex(0x667521E4))

                    pred_index = getPredBlockIndex(block)
                    next_states.append(pred_index)

                elif block_start_ea == 0x43420:
                    next_states.append(hex(0xE4DBC33F))
                    next_states.append(hex(0x667521E4))

                    pred_index = getPredBlockIndex(block)
                    next_states.append(pred_index)

                elif block_start_ea == 0x434ac:
                    next_states.append(hex(0xBD9FBBA))
                    next_states.append(hex(0x5338AB80))

                    pred_index = getPredBlockIndex(block)
                    next_states.append(pred_index)

                elif block_start_ea == 0x434cc:
                    next_states.append(hex(0x146E0C87))
                    next_states.append(hex(0x1B166FED))

                    pred_index = getPredBlockIndex(block)
                    next_states.append(pred_index)

        if  mnem == "MOV" and block_end_ea == loop_end_ea:
            mov_1 = idc.get_operand_value(last_ins_addr,1)
            next_states.append(hex(mov_1))

            pred_index = getPredBlockIndex(block)
            next_states.append(pred_index)

        if mnem == "RET": #添加ret块
            while (1):
                # MOV             W9, #0x146E0C87
                # CMP             W8, W9
                # B.NE            loc_43120

                preds = block.preds()
                preds_list = list(preds)
                block = preds_list[0]
                pred_ea = block.start_ea
                mnem = idc.print_insn_mnem(pred_ea)
                if mnem == "MOV":
                    MOV_ea = pred_ea
                    pred_ea = idc.next_head(pred_ea)
                    mnem = idc.print_insn_mnem(pred_ea)
                    if mnem == "CMP":
                        pred_ea = idc.next_head(pred_ea)
                        mnem = idc.print_insn_mnem(pred_ea)
                        if mnem == "B.NE":
                            mov_1 = idc.get_operand_value(MOV_ea, 1)
                            next_states.append(None)
                            next_states.append(hex(mov_1))
                            break

        if next_states:
            state_map[hex(block_start_ea)] = next_states

    print(state_map)
    return state_map

def getSuccBlockAddrFromMap(state_map,index):
    for key in state_map:
        block_ea = int(key,16)
        targets = state_map[key]

        if len(targets) == 2:
            pred = targets[1]
            if index == pred:#如果A真实块要跳转的索引和B真实块的前驱模块所具备的索引相等,那么直接返回B真实块地址
                return hex(block_ea)
        if len(targets) == 3:
            pred = targets[2]
            if index == pred:
                return hex(block_ea)
    return None

def verifyBlockLink(state_map,fun_start,ret_block_ea,next_states):
    value = state_map[fun_start]
    next_states.append(fun_start)

    if len(value) == 3:
        #进入这里 fun_start即是支配节点
        for i in range(2):
            tmp = next_states.copy()    #获取到支配节点数组
            index = value[i]
            addr = getSuccBlockAddrFromMap(state_map, index)
            # print("支配节点:", fun_start,"-->",addr)
            if addr == None:    #如果获取的地址为空，需要对应补上需要的后继块
                print("array3 无法找到后继块:",tmp,index)
                return None
            if addr == ret_block_ea:
                tmp.append(addr)
                print(tmp)
            else:
                verifyBlockLink(state_map,addr,ret_block_ea,tmp)

    elif len(value) == 2:
        index = value[0]
        addr = getSuccBlockAddrFromMap(state_map, index)

        if addr == None:
            print("array2 无法找到后继块:", next_states, hex(index))
            return None
        if addr == ret_block_ea:
            next_states.append(addr)
            print(next_states)
        else:
            verifyBlockLink(state_map, addr, ret_block_ea, next_states)

def findRETBlock(func_ea):
    func = idaapi.get_func(func_ea)
    blocks = idaapi.FlowChart(func)  # 获取方法中所有的基本块
    for block in blocks:
        block_end_ea = block.end_ea
        last_ins_ea = idc.prev_head(block_end_ea)
        mnem = idc.print_insn_mnem(last_ins_ea)
        if mnem == "RET":
            return block

def verifyLinkMain(state_map,fun_start):
    next_states = []
    ret_block = findRETBlock(fun_start)
    ret_block_ea = ret_block.start_ea#获取ret块地址
    verifyBlockLink(state_map, hex(fun_start), hex(ret_block_ea), next_states)#开始执行验证程序



def getBlockByAddress(ea):
    # 获取地址所在的函数
    func = idaapi.get_func(ea)
    if not func:
        print(f"地址 {hex(ea)} 不在任何函数中")
        return None
    # 创建控制流图
    blocks = idaapi.FlowChart(func)

    # 遍历所有块
    for block in blocks:
        # 检查地址是否在当前块中
        if block.start_ea <= ea < block.end_ea:
            # print(f"地址 {hex(ea)} 在块 {hex(block.start_ea)} - {hex(block.end_ea)} 中")
            return block

    print(f"地址 {hex(ea)} 未找到对应的块")
    return None

def patchBranch(src_addr, dest_addr,op_value = 0):
    # print("src_addr:",hex(src_addr),"dest_addr:",dest_addr)

    # CSEL W8, W9, W8, EQ
    CSEL_ea = idc.prev_head(src_addr)
    CSEL_3 = idc.print_operand(CSEL_ea,3)
    if op_value == 1:
        if CSEL_3 == "EQ":
                encoding, count = ks.asm(f'b.eq {dest_addr}', CSEL_ea)
        if CSEL_3 == "NE":
                encoding, count = ks.asm(f'b.ne {dest_addr}', CSEL_ea)
        if CSEL_3 == "GT":
                encoding, count = ks.asm(f'b.gt {dest_addr}', CSEL_ea)
        src_addr = CSEL_ea
    else:
        encoding, count = ks.asm(f'b {dest_addr}', src_addr)

    if not count:
        print('ks.asm err')
    else:
        for i in range(4):
            idc.patch_byte(src_addr + i, encoding[i])
            # print("patch success:",hex(src_addr),dest_addr)

def rebuildControlFlow(state_map):
    for block in state_map:
        block_ea = int(block,16)#需要把字符串转成int
        # 获取真实块保存的前驱、后继链接块索引
        value = state_map[block]
        # 查找块尾的跳转指令
        endEa = getBlockByAddress(block_ea).end_ea

        last_insn_ea = idc.prev_head(endEa)
        if idc.print_insn_mnem(last_insn_ea) == "B":
            # 如果是无条件跳转(B)
            if len(value) == 2:
                succ_index = value[0] #当前真实块的后继块索引
                if succ_index == None: #return块没有后继,过滤掉它
                    continue
                jmp_addr = getSuccBlockAddrFromMap(state_map,succ_index) #获取后继索引对应的真实块地址
                patchBranch(last_insn_ea, jmp_addr)

            # 如果是条件跳转（CSEL）
            elif len(value) == 3:
                succ_0 = value[0] #后继块的索引值
                jmp_addr_0 = getSuccBlockAddrFromMap(state_map, succ_0) #后继块的地址
                patchBranch(last_insn_ea, jmp_addr_0,1)

                succ_1 = value[1]   #后继块的索引值
                jmp_addr_1 = getSuccBlockAddrFromMap(state_map, succ_1)
                patchBranch(last_insn_ea, jmp_addr_1)
        if idc.print_insn_mnem(last_insn_ea) == "MOV":
            succ_index = value[0]  # 当前真实块的后继块索引
            # if succ_index == None:  # return块没有后继,过滤掉它
            #     continue
            jmp_addr = getSuccBlockAddrFromMap(state_map, succ_index)  # 获取后继索引对应的真实块地址
            patchBranch(last_insn_ea, jmp_addr)

def findDispatchers(func_start,num = 10):
    func = idaapi.get_func(func_start)
    blocks = idaapi.FlowChart(func)
    pachers = []
    for block in blocks:
        preds = block.preds()
        preds_list = list(preds)
        if len(preds_list) > num:
            pachers.append(block)
    return pachers

def deObfuscatorFla():
    print("===============START===================")
    fn = 0x43058 #函数地址

    patchers = findDispatchers(fn) #获取方法中所有的主分发器块 默认块被引用10次的为主分发器
    print("patchers:",len(patchers))
    if len(patchers) == 0:
        print("未找到主分发器")
        return
    # 这里只对一个主分发器操作，多个主分发器需要额外处理
    for disPatcherBlock in patchers:
        print("主分发器地址:", hex(disPatcherBlock.start_ea))
        stamp = getBlockLink(fn, disPatcherBlock.start_ea)  # 记录真实块链接关系
        verifyLinkMain(stamp,fn)#验证块连接关系是否正确
        rebuildControlFlow(stamp)
    print("===============END===================")

deObfuscatorFla()