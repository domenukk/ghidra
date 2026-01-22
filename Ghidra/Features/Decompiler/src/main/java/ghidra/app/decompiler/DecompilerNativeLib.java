package ghidra.app.decompiler;



public class DecompilerNativeLib {

    static {
        try {
            System.loadLibrary("decomp");
        } catch (UnsatisfiedLinkError e) {
            // Might be loaded manually (e.g. in tests) or not found.
            // If it is strictly required, standard usage will fail later.
            // But for tests that load it via System.load(abspath), this is fine.
            System.err.println("NOTE: System.loadLibrary(\"decomp\") failed: " + e.getMessage());
        }
    }

    public interface ReadCallback {
        int invoke(byte[] buf, int len);
    }

    public interface WriteCallback {
        int invoke(byte[] buf, int len);
    }

    public static native long ghidra_init();
    
    public static native int ghidra_run_loop(long handle, ReadCallback readCb, WriteCallback writeCb, DecompileCallback callback);
    
    public static native void ghidra_cleanup(long handle);
}
