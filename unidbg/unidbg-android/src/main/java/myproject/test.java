package myproject;

import capstone.api.Instruction;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ModuleListener;
import com.github.unidbg.arm.backend.*;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import myproject.trace.KingTrace;

import java.io.*;

class BrInfo {
    public long addr;
    public long target;
}

public class test extends AbstractJni {
    AndroidEmulator emulator;
    VM vm;
    Module module;
    String basePath = "D:\\desktop\\ollvm\\360\\";


    public test() {
        emulator = AndroidEmulatorBuilder
                .for64Bit().addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("cc.ccc.cc")
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("D:\\desktop\\ollvm\\360\\base.apk"));
        vm.setVerbose(true);
        vm.setJni(this);

//        emulator.getBackend().hook_add_new(new CodeHook() {
//            @Override
//            public void hook(Backend backend, long address, int size, Object user) {
//                System.out.println(String.format("%x", address - module.base));
//            }
//
//            @Override
//            public void onAttach(UnHook unHook) {
//
//            }
//
//            @Override
//            public void detach() {
//
//            }
//        }, 1, 0, null);
//

        memory.addModuleListener(new ModuleListener() {
            Module targetModule;

            @Override
            public void onLoaded(Emulator<?> emulator, Module module) {
                System.out.println("module.name " + module.name);
                if (module.name.contains("libjiagu")) {
                    targetModule = module;
//                    emulator.getBackend().hook_add_new(new StrWriteHook(), 1, 0, null);
                    try {
                        emulator.traceCode(module.base, module.base + module.size).setRedirect(
                                new PrintStream(new FileOutputStream(basePath + "log.txt"), true));
                    } catch (FileNotFoundException e) {
                    }

                    KingTrace trace1 = new KingTrace(emulator) {
                        @Override
                        public void onInstruction(Emulator<?> emulator, long address, Instruction insn) {
//                            String insName = insn.getMnemonic();
//                            if (insName.toLowerCase().equals("br")) {
//                                List<String> reg = getInsRegList(insn);
//                                BrInfo br = new BrInfo();
//                                br.addr = address - targetModule.base;
//                                br.target = emulator.getBackend().reg_read(getRegIdx(reg.get(0))).longValue() - targetModule.base;
//                                print(String.format("%x %x", br.addr, br.target));
//                            }
                        }

                        @Override
                        public void init() {
                            try {
                                printStream = new PrintStream(new FileOutputStream(basePath + "log.txt"), true);
                            } catch (FileNotFoundException e) {
                                e.printStackTrace();
                            }
                        }
                    };
//                    emulator.getBackend().hook_add_new(trace1, module.base, module.base + module.size, null);
                }
            }
        });
        DalvikModule dm = vm.loadLibrary(new File("D:\\desktop\\ollvm\\360\\ida\\libjiagu.so"),
                false);
        module = dm.getModule();
        Number result = module.callFunction(emulator, 0x2C80);

        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, module.base);

        byte[] moduleData = new byte[(int) module.size];
        pointer.read(0, moduleData, 0, (int) module.size);
        // 写入文件
        try (FileOutputStream fos = new FileOutputStream("D:\\desktop\\ollvm\\360\\ida\\libjiagu2.so")) {
            fos.write(moduleData);
        } catch (Throwable e) {
        }
    }

    public static void main(String[] args) {
        new test();
    }
}
