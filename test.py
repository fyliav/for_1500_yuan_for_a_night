# import json
# import logging
# import os
# from collections import defaultdict
#
# import angr
# import capstone.arm64
# import claripy
# from angr.analyses import BackwardSlice
# from angr.block import CapstoneInsn, DisassemblerInsn
# from capstone import *
# from keystone import *
#
# logging.getLogger('angr').setLevel(logging.ERROR)
# logging.getLogger('claripy').setLevel(logging.ERROR)
# logging.getLogger('pyvex').setLevel(logging.ERROR)
# logging.getLogger('cle').setLevel(logging.ERROR)
#
# cs = capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM)
# cs.details = True
# ks = keystone.Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
# so_path = r'D:\desktop\ollvm\360\ida\rep.so'
# project = angr.Project(so_path, auto_load_libs=False,
#                        load_options={'main_opts': {'base_addr': 0xC8000}})
#
# state = project.factory.entry_state()
#
# text_start = 0xF3C8C
# # text_start = 1241000
# text_end = 0x1C597C
#
#
# def find_expression_dependencies(target_register, instruction_effects):
#     """
#     逆序遍历instruction_effects，寻找影响目标寄存器的指令。
#     使用数据流分析（活变量分析逆向传播）追踪def-use链。
#
#     参数:
#         target_register: 目标寄存器名称，如 'x8'
#         instruction_effects: 指令效果字典，格式为 {addr: [{'write': [reg_ids], 'read': [reg_ids]}]}
#
#     返回:
#         set: 影响目标寄存器的指令地址集合
#     """
#     dependencies = set()
#     target_reg_id = capstone.arm64.ARM64_REG_X8
#     if target_reg_id == 0:
#         print(f"警告: 未知寄存器 '{target_register}'，无法获取ID")
#         return dependencies
#
#     active_uses = set([target_reg_id])
#
#     addrs = reversed(instruction_effects)
#     for addr in addrs:
#         write_regs = addr['write']
#         read_regs = addr['read']
#
#         # 检查活跃使用与写集的交集：如果有，当前指令定义了活跃变量，加入依赖
#         if active_uses & set(write_regs):
#             dependencies.add(addr)
#             # 更新活跃集（向前传播）：
#             # - 添加读集（这些读的变量在当前指令前必须活跃）
#             active_uses.update(read_regs)
#             # - 移除写集（写后，这些变量不再“活”在当前路径）
#             active_uses -= set(write_regs)
#
#     return dependencies
#
#
# def analyze_block_register_dependencies(project, block_address, target_register):
#     block = project.factory.block(block_address)
#     print(f"分析基本块 0x{block_address:x} (共 {block.instructions} 条指令)")
#     state = project.factory.blank_state(addr=block_address)
#     register_states = {}
#     instruction_effects = []
#
#     current_addr = block_address
#     for i in range(block.instructions):
#         insn = block.capstone.insns[i]
#         print(f"\n指令 {i + 1}/{block.instructions}: 0x{current_addr:x} - {insn.mnemonic} {insn.op_str}")
#         succ = state.step(num_inst=1)
#         if len(succ.flat_successors) == 0:
#             print("执行失败，没有后继状态")
#             break
#
#         state = succ.flat_successors[0]
#         reg_value = state.registers.load(target_register)
#         register_states[current_addr] = reg_value
#
#         instruction_effects.append({
#             "addr": current_addr,
#             'write': insn.regs_write,
#             'read': insn.regs_read,
#         })
#
#         current_addr = state.addr
#         if current_addr not in block.instruction_addrs:
#             print(f"执行超出基本块范围 (0x{current_addr:x})")
#             break
#
#     if register_states:
#         last_addr = list(register_states.keys())[-1]
#         final_value = register_states[last_addr]
#
#         print(f"\n{'=' * 50}")
#         print(f"最后一条指令 (0x{last_addr:x}) 的寄存器 {target_register} 值:")
#         print(f"表达式: {final_value}")
#
#         dependencies = find_expression_dependencies(target_register, instruction_effects)
#         print(f"\n寄存器 {target_register} 的值依赖于以下指令:")
#         for addr in dependencies:
#             insn = project.factory.disassembly(addr)
#             print(f"  0x{addr:x}: {insn.mnemonic} {insn.op_str}")
#     return instruction_effects
#
#
# effects = analyze_block_register_dependencies(project, 0xFEBB0, "x8")
from capstone import *
from capstone.arm import *

# 示例二进制指令（ARM 指令集）
CODE = b'\x04\xe0\x2d\xe5\x00\x00\xa0\xe3\x04\xf0\x9d\xe4'  # 示例指令

# 初始化 Capstone 反汇编器
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True  # 启用详细模式

# 反汇编并解析指令
for insn in md.disasm(CODE, 0x1000):  # 起始地址为 0x1000
    print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")

    # 获取寄存器读写信息
    if insn.regs_read:
        regs_read = [insn.reg_name(r) for r in insn.regs_read]
        print(f"  Registers read: {', '.join(regs_read)}")
    if insn.regs_write:
        regs_write = [insn.reg_name(r) for r in insn.regs_write]
        print(f"  Registers written: {', '.join(regs_write)}")
