package ghidra.app.decompiler;



public class DecompilerNativeLib {

    public interface ReadCallback {
        int invoke(long handle, byte[] buf, int len);
    }

    public interface WriteCallback {
        int invoke(long handle, byte[] buf, int len);
    }

    public static native long ghidra_init();
    
    public static native int ghidra_run_loop(long handle, ReadCallback read_cb, WriteCallback write_cb);
    
    public static native void ghidra_cleanup(long handle);
}
