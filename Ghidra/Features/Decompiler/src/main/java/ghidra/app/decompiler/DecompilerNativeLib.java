package ghidra.app.decompiler;

import com.sun.jna.Callback;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

public interface DecompilerNativeLib extends Library {
    DecompilerNativeLib INSTANCE = Native.load("decomp", DecompilerNativeLib.class);

    interface ReadCallback extends Callback {
        int invoke(Pointer handle, Pointer buf, int len);
    }

    interface WriteCallback extends Callback {
        int invoke(Pointer handle, Pointer buf, int len);
    }

    Pointer ghidra_init();
    
    int ghidra_run_loop(Pointer handle, ReadCallback read_cb, WriteCallback write_cb);
    
    void ghidra_cleanup(Pointer handle);
}
