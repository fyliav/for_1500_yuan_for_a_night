package myproject.trace;

import capstone.Capstone;
import capstone.api.Instruction;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.backend.*;
import com.github.unidbg.listener.TraceCodeListener;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.utils.Inspector;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class KingTrace implements CodeHook, TraceCodeListener {


    abstract public void init();

    final Emulator<?> emulator;
    int MaxLengthLibraryName;
    Map<String, Integer> reg_names;
    Pattern regPattern;
    public PrintStream printStream;

    public KingTrace(Emulator<?> emulator) {
        this.emulator = emulator;
        if (this.emulator.is64Bit()) {
            reg_names = GlobalData.arm64_reg_names;
            regPattern = Pattern.compile("([wx][0-9]+)|sp|ip|pc");
        } else {
            reg_names = GlobalData.arm_reg_names;
            regPattern = Pattern.compile("([r][0-9]+)|sp|ip|pc");
        }
        MaxLengthLibraryName = emulator.getMemory().getMaxLengthLibraryName().length();
        init();
    }

    public void print(String msg) {
        if (printStream != null) {
            printStream.println(msg);
        }
    }

    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        try {
            Memory memory = this.emulator.getMemory();
            Module module = memory.findModuleByAddress(address);
            if (GlobalData.ignoreModuleList.contains(module.name)) {
                return;
            }
            Capstone.CsInsn[] insns = (Capstone.CsInsn[]) this.emulator.disassemble(address, size, 0);
            if (insns == null || insns.length != 1) {
                throw new IllegalStateException("insns=" + Arrays.toString(insns));
            }
            printTrace(backend, insns, address);
            onInstruction(emulator, address, insns[0]);
        } catch (BackendException e) {
            throw new IllegalStateException(e);
        }
    }

    private void dump_ldr(Backend backend, String Opstr) {
        if (!GlobalData.is_dump_ldr) {
            return;
        }
        String pattern = "\\[(.+?)\\]";
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(Opstr);
        if (m.find()) {
            String ldrRight = m.group(1);
            String[] rights = ldrRight.split(",");
            String regRight = rights[0];
            String valueRight = rights[1];
            Integer regIndex = reg_names.get(regRight.toUpperCase());
            if (regIndex == 0) {
                throw new IllegalStateException("not found regname:" + regRight);
            }
            Number regRightValue = backend.reg_read(regIndex);
            long right;
            if (reg_names.containsKey(valueRight.toUpperCase())) {
                Integer regIndex2 = reg_names.get(valueRight.toUpperCase());
                Number regRightValue2 = backend.reg_read(regIndex2);
                if (emulator.is64Bit()) {
                    right = regRightValue.longValue() + regRightValue2.longValue();
                } else {
                    right = regRightValue.intValue() + regRightValue2.intValue();
                }
            } else {
                valueRight = valueRight.replace("#", "").trim();
                long valueRightInt;
                if (valueRight.startsWith("0x")) {
                    valueRight = valueRight.replace("0x", "");
                    valueRightInt = Integer.parseInt(valueRight, 16);
                } else {
                    valueRightInt = Integer.parseInt(valueRight);
                }
                if (emulator.is64Bit()) {
                    right = regRightValue.longValue() + valueRightInt;
                } else {
                    right = regRightValue.intValue() + valueRightInt;
                }

            }
            try {
                long unsignedValue = OtherTools.toUnsignedLong(right);
                byte[] dump_buff = backend.mem_read(unsignedValue, GlobalData.dump_str_size);
                Inspector.inspect(dump_buff, String.format("ldr_right_address:%x dump", unsignedValue));
            } catch (Exception ex) {

            }
        }
    }

    public Integer getRegIdx(String name) {
        return reg_names.get(name.toUpperCase());
    }

    public ArrayList<String> getInsRegList(Instruction ins) {
        Matcher m = regPattern.matcher(ins.getOpStr());
        ArrayList<String> regs = new ArrayList<>();
        while (m.find()) {
            regs.add(m.group(1));
        }
        return regs;
    }

    private void printTrace(Backend backend, Capstone.CsInsn[] insns, long address) {
        for (Capstone.CsInsn ins : insns) {
            //查询上否有上一条缓存的指令，有的话，则查询上次的改动寄存器的数值。然后再打印
            if (GlobalData.has_pre && !GlobalData.pre_regname.equals("")) {
                Integer regindex = reg_names.get(GlobalData.pre_regname.get(0).toUpperCase());
                Number regvalue = backend.reg_read(regindex);
                if (emulator.is32Bit() || GlobalData.pre_regname.get(0).toUpperCase().startsWith("W")) {
                    GlobalData.pre_codestr += String.format("\t//%s=0x%x", GlobalData.pre_regname.get(0), OtherTools.toUnsignedInt(regvalue.intValue()));
                } else {
                    GlobalData.pre_codestr += String.format("\t//%s=0x%x", GlobalData.pre_regname.get(0), OtherTools.toUnsignedLong(regvalue.longValue()));
                }

                print(GlobalData.pre_codestr);
                //是否要dump汇编str
                if (GlobalData.is_dump_str) {
                    if (GlobalData.pre_codestr.contains("str")) {
                        if (regvalue.longValue() > 0xffff) {
                            try {
                                byte[] dump_buff = backend.mem_read(regvalue.longValue(), GlobalData.dump_str_size);
                                Inspector.inspect(dump_buff, String.format("str_address:%x dump", regvalue.longValue()));
                            } catch (Exception ex) {

                            }
                        }
                    }
                }
//                //是否要dump汇编的ldr指令
                if (GlobalData.is_dump_ldr) {
                    if (GlobalData.pre_codestr.contains("ldr")) {
                        //先尝试把ldr的结果当成指针去尝试读取
                        if (regvalue.longValue() > 0xffff) {
                            try {
                                byte[] dump_buff = backend.mem_read(regvalue.longValue(), GlobalData.dump_str_size);
                                Inspector.inspect(dump_buff, String.format("ldr_left_address:%x dump", regvalue.longValue()));
                            } catch (Exception ex) {

                            }
                        }
                    }
                }

                GlobalData.pre_codestr = "";
                GlobalData.pre_regname = null;
                GlobalData.has_pre = false;
            }
            //内存监控，发生变化就打印
//            if (GlobalData.watch_address.size()>0){
//                for (Integer watch:GlobalData.watch_address.keySet()) {
//                    String hexstr= OtherTools.byteToString(idata);
//                    byte[] idata= backend.mem_read(watch,GlobalData.watch_print_size);
//                    if(GlobalData.watch_address.get(watch).equals(hexstr)){
//                        continue;
//                    }
//                    GlobalData.watch_address.put(watch,hexstr);
//                    Inspector.inspect(idata, String.format("watch_address:%x onchange",watch));
//                }
//            }

            //拼接当前行的汇编指令
            String opstr = ARM.assembleDetail(emulator, ins, address, false, MaxLengthLibraryName);
            List<String> regs = getInsRegList(ins);
            GlobalData.pre_regname = regs;
            //如果当前指令没有寄存器。则直接打印。下次无需再打印上次的结果
            if (regs.size() <= 0) {
                GlobalData.has_pre = false;
                GlobalData.pre_codestr = "";
                GlobalData.pre_regname = null;
                print(opstr);
                continue;
            }
            String curRegs = "";
            for (String reg : regs) {
                Integer regindex = reg_names.get(reg.toUpperCase());
                Number regvalue = backend.reg_read(regindex);
                if (emulator.is32Bit() || reg.toUpperCase().startsWith("W")) {
                    curRegs += String.format("%s=0x%x\t", reg, OtherTools.toUnsignedInt(regvalue.intValue()));
                } else {
                    curRegs += String.format("%s=0x%x\t", reg, OtherTools.toUnsignedLong(regvalue.longValue()));
                }
            }
//            if(opstr.contains(" ldr")){
//                String ldrstr=opstr.split("ldr")[1];
//                dump_ldr(backend,ldrstr);
//            }

            GlobalData.pre_codestr = opstr + GlobalData.print_split + curRegs;
            GlobalData.has_pre = true;
            address += ins.size;
        }
    }

    @Override
    public void onAttach(UnHook unHook) {

    }

    @Override
    public void detach() {

    }
}
