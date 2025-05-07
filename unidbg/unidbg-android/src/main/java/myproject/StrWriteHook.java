package myproject;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.WriteHook;

import java.util.HashMap;
import java.util.Map;

public class StrWriteHook implements WriteHook  {
    public Map<Long, byte[]> dstr_datas = new HashMap<Long, byte[]>();

    @Override
    public void onAttach(UnHook unHook) {

    }

    @Override
    public void detach() {

    }

    public static byte[] longToBytesBig(long n) {
        byte[] b = new byte[8];
        b[7] = (byte) (n & 0xff);
        b[6] = (byte) (n >> 8 & 0xff);
        b[5] = (byte) (n >> 16 & 0xff);
        b[4] = (byte) (n >> 24 & 0xff);
        b[3] = (byte) (n >> 32 & 0xff);
        b[2] = (byte) (n >> 40 & 0xff);
        b[1] = (byte) (n >> 48 & 0xff);
        b[0] = (byte) (n >> 56 & 0xff);
        return b;
    }

    public static byte[] longToBytesLittle(long n) {
        byte[] b = new byte[8];
        b[0] = (byte) (n & 0xff);
        b[1] = (byte) (n >> 8 & 0xff);
        b[2] = (byte) (n >> 16 & 0xff);
        b[3] = (byte) (n >> 24 & 0xff);
        b[4] = (byte) (n >> 32 & 0xff);
        b[5] = (byte) (n >> 40 & 0xff);
        b[6] = (byte) (n >> 48 & 0xff);
        b[7] = (byte) (n >> 56 & 0xff);
        return b;
    }

    @Override
    public void hook(Backend backend, long address, int size, long value, Object user) {
        byte[] writedata = longToBytesLittle(value);
        System.out.println(new String(writedata));
//        byte[] resizeWriteData = new byte[size];
//        System.arraycopy(writedata, 0, resizeWriteData, 0, size);
//        dstr_datas.put(address, resizeWriteData);
    }
}
