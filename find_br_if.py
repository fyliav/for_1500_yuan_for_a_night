import json
import logging
import os
import angr
import capstone.arm64
from angr.block import CapstoneInsn, DisassemblerInsn
from capstone import *

logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)

disasm = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

project = angr.Project(r'D:\desktop\ollvm\360\ida\rep.so', auto_load_libs=False,
                       load_options={'main_opts': {'base_addr': 0xC8000}})

state = project.factory.entry_state()

text_start = 0xF3C8C
# text_start = 1241000
text_end = 0x1C597C


class BrIfInfo:
    def __init__(self):
        self.cmp = None
        self.adrp = None
        self.cset = None
        self.add = None
        self.ldr = None
        self.br = None
        self.jump_reg = None
        self.ldr_base = None
        self.ldr_index = None
        self.cmp_reg = None
        self.block_addr = None


class BrIfInfoEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, BrIfInfo):
            def serialize_instruction(inst):
                if inst is None:
                    return None
                return {
                    "address": inst.address,
                    "mnemonic": inst.mnemonic,
                    "op_str": inst.op_str,
                }

            return {
                "cmp": serialize_instruction(obj.cmp),
                "adrp": serialize_instruction(obj.adrp),
                "cset": serialize_instruction(obj.cset),
                "add": serialize_instruction(obj.add),
                "ldr": serialize_instruction(obj.ldr),
                "br": serialize_instruction(obj.br),
                "jump_reg": obj.jump_reg,
                "ldr_base": obj.ldr_base,
                "ldr_index": obj.ldr_index,
                "cmp_reg": obj.cmp_reg,
                "block_addr": obj.block_addr,
            }


def find_br_if():
    def judge_br_if(block: angr.Block):
        br = BrIfInfo()
        br.block_addr = block.addr
        for inst in reversed(block.capstone.insns):
            if inst and hasattr(inst, "mnemonic"):
                if inst.mnemonic == "br":
                    if br.br:
                        print("error br")
                    br.br = inst
                    br.jump_reg = inst.operands[0].value.reg

                if br.br and inst.mnemonic == "ldr":
                    if inst.operands[0].type == CS_OP_REG and inst.operands[0].value.reg == br.jump_reg:
                        br.ldr = inst
                        br.ldr_base = inst.operands[1].value.mem.base
                        br.ldr_index = inst.operands[1].value.mem.index

                if br.ldr and inst.mnemonic == "add":
                    if inst.operands[0].type == CS_OP_REG and inst.operands[0].value.reg == br.ldr_base:
                        br.add = inst

                if br.add and inst.mnemonic == "cset":
                    if inst.operands[0].type == CS_OP_REG and inst.operands[0].value.reg == br.ldr_index:
                        br.cset = inst

                if br.cset and inst.mnemonic == "adrp":
                    if inst.operands[0].type == CS_OP_REG and inst.operands[0].value.reg == br.ldr_base:
                        br.adrp = inst

                if br.adrp and inst.mnemonic == "cmp":
                    if inst.operands[0].type == CS_OP_REG:
                        br.cmp = inst
                        br.cmp_reg = inst.operands[0].value.reg
                        break
        if br.br:
            return br
        return None

    result = []
    current_addr = text_start
    block = project.factory.block(current_addr)
    while current_addr < text_end:
        try:
            info = judge_br_if(block)
            if info:
                result.append(info)
                if len(result) % 10 == 0:
                    open("./br_if.json", "w").write(json.dumps(result, cls=BrIfInfoEncoder))
            if block.size == 0:
                current_addr += 4
            else:
                current_addr += block.size
            block = project.factory.block(current_addr)
            if current_addr % 10000 == 0:
                print("find_br_if", current_addr)
        except Exception as e:
            print(e)
    open("./br_if.json", "w").write(json.dumps(result, cls=BrIfInfoEncoder))
    return result


def load_br_if():
    def json2BrIfInfo(item):
        def json2inst(inst_json):
            if not inst_json:
                return None
            code = state.memory.load(inst_json["address"], 4)
            code_bytes = state.solver.eval(code, cast_to=bytes)
            for inst in disasm.disasm(code_bytes, inst_json["address"]):
                return inst
            return None

        result = BrIfInfo()
        result.cmp = json2inst(item["cmp"])
        result.adrp = json2inst(item["adrp"])
        result.cset = json2inst(item["cset"])
        result.add = json2inst(item["add"])
        result.ldr = json2inst(item["ldr"])
        result.br = json2inst(item["br"])
        result.jump_reg = item["jump_reg"]
        result.ldr_base = item["ldr_base"]
        result.ldr_index = item["ldr_index"]
        result.cmp_reg = item["cmp_reg"]
        result.block_addr = item["block_addr"]
        return result

    result = []
    data = json.loads(open("./br_if.json", "r").read())
    for item in data:
        result.append(json2BrIfInfo(item))
    return result


def filter_br_if(list):
    result = []
    for item in list:
        if item.cmp is not None:
            result.append(item)
    return result


def sym_vale_to_asm(value):
    return ""


def evlBr(br: BrIfInfo):
    block: angr.Block = project.factory.block(br.block_addr)
    state = project.factory.blank_state(addr=block.addr)
    state.options.add(angr.options.CALLLESS)
    sim = project.factory.simgr(state)
    pc = block.addr
    cs = capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    while pc < block.addr + block.size - 4:
        sim.step(num_inst=1)
        pc += 4
        for active_state in sim.active[:]:
            active_state.regs.pc = pc
    if len(sim.active) != 1:
        print("active_state len ", len(sim.active))
        return None
    reg = cs.reg_name(br.jump_reg)
    reg_value = sim.active[0].regs.get(reg)
    if sim.active[0].solver.symbolic(reg_value):
        print(f"寄存器 {reg} 的值是符号化的")
        return {
            "asm": sym_vale_to_asm(reg_value)
        }
    else:
        return {
            "value": sim.active[0].solver.eval(reg_value, cast_to=int)
        }


def make_pathc_info(br):
    evlBr(br)


# find_br_if()
br_list = load_br_if()
br_if_list = filter_br_if(br_list)
make_pathc_info(br_if_list[0])
