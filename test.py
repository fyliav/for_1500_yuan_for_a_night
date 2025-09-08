import json
import logging
import os
import angr
import capstone.arm64
from angr.block import CapstoneInsn, DisassemblerInsn
import claripy
from capstone import *

logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)

disasm = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

project = angr.Project(r'D:\desktop\tmp\libtiny.so', auto_load_libs=False,
                       load_options={'main_opts': {'base_addr': 0}})

state = project.factory.entry_state()


def evlBr(block_addr):
    block: angr.Block = project.factory.block(block_addr)
    state = project.factory.blank_state(addr=block.addr)
    state.options.add(angr.options.CALLLESS)
    sim = project.factory.simulation_manager(state)
    pc = block.addr
    cs = capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for idx in range(0, 30):
        setattr(state, "x" + str(idx), claripy.BVS(f"x{idx}_sym", 64))
    while pc < block.addr + block.size - 4:
        sim.step(num_inst=1)
        pc += 4
        for active_state in sim.active[:]:
            active_state.regs.pc = pc
    if len(sim.active) != 1:
        print("active_state len ", len(sim.active))
        return None
    # reg = cs.reg_name(br.jump_reg)
    reg = "x9"
    reg_value = sim.active[0].regs.get(reg)
    if sim.active[0].solver.symbolic(reg_value):
        print(f"寄存器 {reg} 的值是符号化的")
        return {
            "asm": ""
        }
    else:
        return {
            "value": sim.active[0].solver.eval(reg_value, cast_to=int)
        }


evlBr(0x19CD5C)
