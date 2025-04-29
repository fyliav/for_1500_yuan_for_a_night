import json
import logging
import pathlib

import angr
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from cart.cart import text_type
from markdown_it.rules_core import text_join

logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)

disasm = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

project = angr.Project(r'D:\desktop\ollvm\vbox\l03c1596c_a64.so', auto_load_libs=False,
                       load_options={'main_opts': {'base_addr': 0}})
state = project.factory.entry_state()
base = project.loader.min_addr

text_section = None
for section in project.loader.main_object.sections:
    if section.name == '.text':
        text_section = section
        break

text_start = text_section.vaddr
text_end = text_section.vaddr + 0x294df4
print("base", hex(base))
print("text_start", hex(text_start))
print("text_end", hex(text_end))

current_addr = text_start
brlist = []

if pathlib.Path.exists("./br.json"):
    br_json = open("./br.json").read()
    brlist = json.loads(br_json)
else:
    while current_addr < text_end:
        code = state.memory.load(current_addr, 4)
        code_bytes = state.solver.eval(code, cast_to=bytes)
        for instr in disasm.disasm(code_bytes, current_addr):
            if instr and hasattr(instr, "mnemonic") and instr.mnemonic == "br":
                print(instr)
                brlist.append({
                    "addr": current_addr,
                    "reg": instr.op_str,
                })
        current_addr += 4
    open("./br.json", "w").write(json.dumps(brlist))

print("br", brlist)


def trace_hook(state):
    pc = state.solver.eval(state.regs.pc) - base
    code = state.memory.load(pc, 4)
    code_bytes = state.solver.eval(code, cast_to=bytes)
    for instr in disasm.disasm(code_bytes, pc):
        print(f"PC: 0x{pc:x} | {instr.mnemonic} {instr.op_str}")

    # print_reg(state)


def evlBr(addr, reg):
    print("evlBr", "addr", hex(addr), "reg", reg)
    start = max(text_start, addr - 0x200)
    if start < text_start:
        start = text_start
    state = project.factory.blank_state(addr=start)
    state.options.add(angr.options.CALLLESS)  # Avoid external calls
    sim = project.factory.simgr(state)
    lastPc = start
    # Step until target address, limit path explosion
    while lastPc <= addr:
        sim.step(num_inst=1)
        if not len(sim.active) == 1:
            print("---end---", hex(lastPc + 4))
            state = project.factory.blank_state(addr=lastPc + 4)
            sim = project.factory.simgr(state)
            sim.step(num_inst=1)
            lastPc += 4
            continue

        for active_state in sim.active[:]:
            pc = active_state.solver.eval(active_state.regs.pc)
            if pc < lastPc or pc > addr:
                print("---end2---", hex(lastPc + 4))
                state = project.factory.blank_state(addr=lastPc + 4)
                sim = project.factory.simgr(state)
                sim.step(num_inst=1)
                lastPc += 4
                break

            lastPc = pc
            if pc == addr:
                try:
                    reg_value = active_state.regs.get(reg)
                    if active_state.solver.symbolic(reg_value):
                        print(f"寄存器 {reg} 的值是符号化的")
                        return "sym"
                    concrete_value = active_state.solver.eval(reg_value, cast_to=int)
                    print(f"寄存器 {reg} 在 0x{addr:x} 的值: 0x{concrete_value:x}")
                    return concrete_value
                except Exception as e:
                    print(f"无法获取寄存器 {reg} 的值: {e}")
                    return "error"

    print(f"未找到到达 0x{addr:x} 的有效状态")
    return "not find"


dump = 0
for item in brlist:
    dump += 1
    if dump % 10 == 0:
        open("./br.json", "w").write(json.dumps(brlist))
    try:
        if item.get("real") is None:
            item["real"] = evlBr(item["addr"], item["reg"])
    except Exception as e:
        print(e)
print(brlist)

# def trace_register_value(project, target_addr, register_name):
#     target_block = project.factory.block(0x016E900 + base)
#
#     observation_points = [(target_addr, None, OP_BEFORE)]
#
#     rda = project.analyses.ReachingDefinitions(
#         subject=target_block,
#         observation_points=observation_points,
#         track_tmps=True,
#         track_consts=True
#     )
#
#     register_offset = project.arch.registers[register_name][0]
#
#     results = []
#     for defn in rda.all_definitions:
#         if defn.offset == register_offset:
#             code_loc = defn.codeloc
#
#             try:
#                 block = project.factory.block(code_loc.ins_addr)
#                 instr = block.capstone.insns[0]
#                 asm = f"{instr.mnemonic} {instr.op_str}"
#             except Exception:
#                 asm = "Unknown instruction"
#
#             # 提取符号表达式
#             value_expr = defn.data.ast if hasattr(defn.data, 'ast') else defn.data
#
#             results.append({
#                 'address': hex(code_loc.ins_addr),
#                 'instruction': asm,
#                 'value': value_expr
#             })
#
#     return results
#
#
# # 使用示例
#
# target_address = base + 0x16E920
# register = "x6"
#
# analysis_result = trace_register_value(project, target_address, register)
#
# # 打印结果
# print(f"寄存器 {register} 在地址 {hex(target_address)} 处的值来源：")
# for item in analysis_result:
#     print(f"指令地址：{item['address']}")
#     print(f"指令内容：{item['instruction']}")
#     print(f"值表达式：{item['value']}\n")
