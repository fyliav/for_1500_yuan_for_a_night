# import json
# import logging
# import os
# import angr
# import capstone.arm64
# import claripy
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
# block = project.factory.block(0xFEBB0, opt_level=0)
# block.vex.pp()

import capstone as cs
import pyvex
import archinfo

machine_code = bytes.fromhex(
    "1F0000F1C90700F0E8179F1A29E13A91285968F8B65737A9B58359F8B7F333A9BA6F38A9B98312F8B88315F800011FD6".replace(" ", ""))

irsb = pyvex.lift(machine_code, 0xFEBB0, archinfo.ArchAArch64(), opt_level=0)

print(irsb)
statements = list(reversed(irsb.statements))
dependencies_idx = []
interested_value = {}
target_reg = archinfo.ArchAArch64().get_register_offset("x8")


def get_add_mapping(statements):
    result = {}
    last_addr = None
    for idx in range(len(statements)):
        stmt = statements[idx]
        if isinstance(stmt, pyvex.IRStmt.IMark):
            last_addr = stmt.addr
        else:
            result[idx] = last_addr
    return result


def get_tmp_offset_key(offset):
    return f"tmp_{offset}"


def get_reg_offset_key(offset):
    return f"reg_{offset}"


interested_value[get_reg_offset_key(target_reg)] = {
    "type": "reg",
    "value": target_reg,
}


def make_interested_value(datas):
    result = {}
    if not isinstance(datas, list) and not isinstance(datas, tuple):
        datas = [datas]
    for data in datas:
        if isinstance(data, pyvex.expr.RdTmp):
            result[get_tmp_offset_key(data.tmp)] = {
                "type": "tmp",
                "value": data.tmp,
            }
        elif isinstance(data, pyvex.expr.Unop):
            result.update(make_interested_value(data.args))
        elif isinstance(data, pyvex.expr.Load):
            print("waring read mem")
            result.update(make_interested_value(data.addr))
        elif isinstance(data, pyvex.expr.Binop):
            result.update(make_interested_value(data.args))
        elif isinstance(data, pyvex.expr.CCall):
            result.update(make_interested_value(data.args))
        elif isinstance(data, pyvex.expr.ITE):
            result.update(make_interested_value(data.child_expressions))
            result.update(make_interested_value(data.cond))
        elif isinstance(data, pyvex.expr.Get):
            result[get_reg_offset_key(data.offset)] = {
                "type": "reg",
                "value": data.offset,
            }
        elif isinstance(data, pyvex.expr.Const):
            pass
        else:
            print("unknow put.data op", data)
    return result


for idx in range(len(statements)):
    stmt = statements[idx]

    find_key = None
    find_value = None

    if isinstance(stmt, pyvex.IRStmt.IMark):
        continue
    elif isinstance(stmt, pyvex.IRStmt.Put):
        if get_reg_offset_key(stmt.offset) in interested_value.keys():
            find_key = get_reg_offset_key(stmt.offset)
            find_value = make_interested_value(stmt.data)
    elif isinstance(stmt, pyvex.IRStmt.WrTmp):
        if get_tmp_offset_key(stmt.tmp) in interested_value.keys():
            find_key = get_tmp_offset_key(stmt.tmp)
            find_value = make_interested_value(stmt.data)
    elif isinstance(stmt, pyvex.IRStmt.Store):
        if get_tmp_offset_key(stmt.data.tmp) in interested_value.keys():
            find_key = get_tmp_offset_key(stmt.data.tmp)
            find_value = make_interested_value(stmt.data)
    else:
        print("unknow vex op ", stmt)

    if find_key:
        interested_value.update(find_value)
        del interested_value[find_key]
        dependencies_idx.append(idx)

print(dependencies_idx)
print(interested_value)

count = len(irsb.statements)
addr_mapping = get_add_mapping(irsb.statements)
dependencies_addr = set()
for item in dependencies_idx:
    dependencies_addr.add(addr_mapping[count - item - 1])

dependencies_addr = list(dependencies_addr)
dependencies_addr.sort()
for item in dependencies_addr:
    print(hex(item))
