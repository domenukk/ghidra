package ghidra.app.decompiler;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;



public class DecompileProcessLib extends DecompileProcess {

    private Thread libThread;
    private long libHandle;
    private DecompilerNativeLib.ReadCallback readCb;
    private DecompilerNativeLib.WriteCallback writeCb;
    private PipedInputStream cppIn;
    private PipedOutputStream cppOut;

    public DecompileProcessLib() {
        super("libdecomp");
    }

    @Override
    protected void setup() throws IOException {
        if (getDisposeState() != DisposeState.NOT_DISPOSED) {
            throw new IOException("Decompiler has been disposed");
        }
        
        // Initialize streams
        // javaIn (nativeIn) <--- cppOut <--- writeCb
        // javaOut (nativeOut) ---> cppIn ---> readCb
        
        PipedInputStream javaIn = new PipedInputStream(4096 * 16);
        cppOut = new PipedOutputStream(javaIn);
        
        cppIn = new PipedInputStream(4096 * 16);
        PipedOutputStream javaOut = new PipedOutputStream(cppIn);
        
        nativeIn = javaIn;
        nativeOut = javaOut;
        
        // Initialize library
        try {
            libHandle = DecompilerNativeLib.ghidra_init();
        } catch (Throwable t) {
            throw new IOException("Failed to load decompiler library: " + t.getMessage(), t);
        }
        
        // Define callbacks
        readCb = (handle, buf, len) -> {
            try {
                int n = cppIn.read(buf, 0, len);
                return (n < 0) ? 0 : n;
            } catch (IOException e) {
                return 0;
            }
        };
        
        writeCb = (handle, buf, len) -> {
            try {
                cppOut.write(buf, 0, len);
                cppOut.flush();
                return len;
            } catch (IOException e) {
                return 0;
            }
        };
        
        // Start thread
        libThread = new Thread(() -> {
            DecompilerNativeLib.ghidra_run_loop(libHandle, readCb, writeCb);
        }, "DecompilerLibThread");
        libThread.setDaemon(true);
        libThread.start();
        
        statusGood = true;
    }
    
    @Override
    public void dispose() {
        super.dispose();
        // Closing streams should unblock the thread
        try {
            if (cppIn != null) cppIn.close();
            if (cppOut != null) cppOut.close();
        } catch (IOException e) {
            // ignore
        }
    }
}
