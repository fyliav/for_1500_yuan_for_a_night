import json
import logging
import os
import angr
import capstone.arm64
import claripy
from angr.block import CapstoneInsn, DisassemblerInsn
from capstone import *
from keystone import *

logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)

cs = capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM)
ks = keystone.Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
so_path = r'D:\desktop\ollvm\360\ida\rep.so'
project = angr.Project(so_path, auto_load_libs=False,
                       load_options={'main_opts': {'base_addr': 0xC8000}})

state = project.factory.entry_state()

text_start = 0xF3C8C
# text_start = 1241000
text_end = 0x1C597C


class BrIfInfo:
    def __init__(self):
        self.cmp: DisassemblerInsn = None
        self.adrp: DisassemblerInsn = None
        self.cset: DisassemblerInsn = None
        self.add: DisassemblerInsn = None
        self.ldr: DisassemblerInsn = None
        self.br: DisassemblerInsn = None
        self.jump_reg = None
        self.ldr_base = None
        self.ldr_index = None
        self.cmp_reg = None
        self.block_addr = None
        self.true_value = None
        self.false_value = None
        self.value = None


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
                "true_value": obj.true_value,
                "false_value": obj.false_value,
                "value": obj.value,
            }


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
    if br.br and br.br.operands[0].type == CS_OP_REG:
        return br
    return None


def find_br_if():
    result = []
    current_addr = text_start
    block = project.factory.block(current_addr)
    while current_addr < text_end:
        try:
            info = judge_br_if(block)
            if info:
                result.append(info)
                if len(result) % 10 == 0:
                    open("br_if.json", "w").write(json.dumps(result, cls=BrIfInfoEncoder))
            if block.size == 0:
                current_addr += 4
            else:
                current_addr += block.size
            block = project.factory.block(current_addr)
            if current_addr % 10000 == 0:
                print("find_br_if", current_addr)
        except Exception as e:
            print(e)
    open("br_if.json", "w").write(json.dumps(result, cls=BrIfInfoEncoder))
    return result


def load_br_if():
    def json2BrIfInfo(item):
        def json2inst(inst_json):
            if not inst_json:
                return None
            code = state.memory.load(inst_json["address"], 4)
            code_bytes = state.solver.eval(code, cast_to=bytes)
            for inst in cs.disasm(code_bytes, inst_json["address"]):
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
        result.true_value = item.get("true_value")
        result.false_value = item.get("false_value")
        return result

    result = []
    data = json.loads(open("br_if.json", "r").read())
    for item in data:
        result.append(json2BrIfInfo(item))
    return result


def filter_br_if(list):
    result = []
    for item in list:
        if item.cmp is not None:
            result.append(item)
    return result


def get_register_name(state, target_bvs):
    for reg_id, reg_name in state.arch.register_names.items():
        try:
            reg_value = getattr(state.regs, reg_name)
            if reg_value is target_bvs:
                return reg_name
        except AttributeError:
            continue
    return None


def find_args_reg(args):
    result = []
    for item in args:
        name = get_register_name(state, item)
        if name:
            result.append(item)
    return result


def get_value_or_reg(state, value):
    if value.symbolic:
        reg = get_register_name(state, value)
        if reg:
            return reg
        return str(value)
    else:
        return state.solver.eval(value)


def ast2asm(state, value):
    if value.op == "If":
        condition = value.args[0]
        return {
            "cond_op": condition.op,
            "cond_l": get_value_or_reg(state, claripy.simplify(condition.args[0])),
            "cond_r": get_value_or_reg(state, claripy.simplify(condition.args[1])),
            "true_value": get_value_or_reg(state, value.args[1]),
            "false_value": get_value_or_reg(state, value.args[2]),
        }
    else:
        print("unknown op " + value.op, hex(state.regs.pc))
        return {}


def disasm(state, pc):
    code = state.memory.load(pc, 4)
    code_bytes = state.solver.eval(code, cast_to=bytes)
    for item in cs.disasm(code_bytes, pc):
        return item
    return None


def evlBr(br: BrIfInfo):
    block: angr.Block = project.factory.block(br.block_addr)
    state = project.factory.blank_state(addr=block.addr)
    state.options.add(angr.options.CALLLESS)
    sim = project.factory.simgr(state)
    pc = block.addr
    while pc < block.addr + block.size - 4:
        # print(disasm(state, pc).mnemonic)
        sim.step(num_inst=1)
        pc += 4
        for active_state in sim.active[:]:
            active_state.regs.pc = pc
    if len(sim.active) != 1:
        print("active_state len ", len(sim.active), hex(block.addr))
        return None
    reg = cs.reg_name(br.jump_reg)
    reg_value = sim.active[0].regs.get(reg)
    if sim.active[0].solver.symbolic(reg_value):
        # print(f"reg {reg} is sym")
        return ast2asm(sim.active[0], reg_value)
    else:
        print(f"reg {reg} is value")
        return {
            "value": sim.active[0].solver.eval(reg_value, cast_to=int)
        }


def make_pathc_info(br_if_list):
    for item in br_if_list:
        r = evlBr(item)
        item.true_value = r.get("true_value")
        item.false_value = r.get("false_value")
        item.value = r.get("value")
    return br_if_list


def bytes_to_chunks(data: bytes) -> list[bytes]:
    return [data[i:i + 4] for i in range(0, len(data), 4)]


def chunks_to_bytes(chunks: list[bytes]) -> bytes:
    return b''.join(chunks)


def move_none_to_end(arr: list) -> list:
    result = arr.copy()
    non_none_pos = 0
    for i in range(len(result)):
        if result[i] is not None:
            result[non_none_pos], result[i] = result[i], result[non_none_pos]
            non_none_pos += 1
    return result


class PatchSo:
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.binary_bytes = f.read()
        self.binary_bytes = bytearray(self.binary_bytes)

    def patch(self, addr, data: bytes):
        addr = project.loader.main_object.addr_to_offset(addr)
        self.binary_bytes[addr:addr + len(data)] = data

    def save(self):
        with open(self.path + "_patch.so", 'wb') as f:
            f.write(self.binary_bytes)


def patch_br_if(br):
    sp = br.cset.op_str.split(",")
    op = sp[1].strip()
    b_inst = None
    b_if_inst = None
    if op == "lt":
        b_if_inst = {
            "op": "b.lt",
            "addr": br.true_value
        }
    elif op == "ne":
        b_if_inst = {
            "op": "b.ne",
            "addr": br.true_value
        }
    elif op == "eq":
        b_if_inst = {
            "op": "b.eq",
            "addr": br.true_value
        }
    elif op == "hi":
        b_if_inst = {
            "op": "b.hi",
            "addr": br.true_value
        }
    elif op == "lo":
        b_if_inst = {
            "op": "b.lo",
            "addr": br.true_value
        }
    elif op == "gt":
        b_if_inst = {
            "op": "b.gt",
            "addr": br.true_value
        }
    else:
        print("unknown op ", op, hex(br.block_addr))
        return
    b_inst = {
        "op": "b",
        "addr": br.false_value
    }

    size = br.br.address - br.cmp.address + 4
    code = state.memory.load(br.cmp.address, size)
    code_bytes = state.solver.eval(code, cast_to=bytes)
    codes = bytes_to_chunks(code_bytes)
    nop_idx = [
        int((br.cset.address - br.cmp.address) / 4),
        int((br.add.address - br.cmp.address) / 4),
        int((br.adrp.address - br.cmp.address) / 4),
        int((br.ldr.address - br.cmp.address) / 4),
        int((br.br.address - br.cmp.address) / 4),
    ]

    nop = ks.asm("nop", 0, True)[0]
    for idx in nop_idx:
        codes[idx] = None
    codes = move_none_to_end(codes)
    for idx in range(0, len(codes)):
        if codes[idx] is None:
            codes[idx] = nop
    b_if_addr = br.cmp.address + size - 8
    b_addr = br.cmp.address + size - 4
    codes[len(codes) - 2] = ks.asm(b_if_inst["op"] + " " + str(b_if_inst["addr"]), b_if_addr, True)[0]
    codes[len(codes) - 1] = ks.asm("b " + str(b_inst["addr"]), b_addr, True)[0]
    codes = chunks_to_bytes(codes)
    return {
        "addr": br.cmp.address,
        "codes": codes
    }


def patch_br(br):
    codes = ks.asm("b " + str(br.br.value), br.br.addres, True)[0]
    return {
        "addr": br.br.address,
        "codes": codes
    }


def patch(br_list):
    patch = PatchSo(so_path)
    result = []
    for br in br_list:
        r = None
        if br.value != None:
            r = patch_br(br)
        else:
            r = patch_br_if(br)
        if r:
            patch.patch(r["addr"], r["codes"])
            r["codes"] = r["codes"].hex()
            result.append(r)
    patch.save()


# br_list = find_br_if()
br_list = load_br_if()
# br_if_list = filter_br_if(br_list)
# br = judge_br_if(project.factory.block(0x109284))
patch(make_pathc_info(br_list))
# print(json.dumps(br_if_list, cls=BrIfInfoEncoder))
