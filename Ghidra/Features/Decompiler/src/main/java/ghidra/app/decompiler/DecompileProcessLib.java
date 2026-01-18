package ghidra.app.decompiler;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import com.sun.jna.Pointer;

public class DecompileProcessLib extends DecompileProcess {

    private Thread libThread;
    private Pointer libHandle;
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
            libHandle = DecompilerNativeLib.INSTANCE.ghidra_init();
        } catch (Throwable t) {
            throw new IOException("Failed to load decompiler library: " + t.getMessage(), t);
        }
        
        // Define callbacks
        readCb = (handle, buf, len) -> {
            try {
                byte[] b = new byte[len];
                int n = cppIn.read(b);
                if (n > 0) {
                    buf.write(0, b, 0, n);
                    return n;
                }
                return 0;
            } catch (IOException e) {
                return 0;
            }
        };
        
        writeCb = (handle, buf, len) -> {
            try {
                byte[] b = buf.getByteArray(0, len);
                cppOut.write(b);
                cppOut.flush();
                return len;
            } catch (IOException e) {
                return 0;
            }
        };
        
        // Start thread
        libThread = new Thread(() -> {
            DecompilerNativeLib.INSTANCE.ghidra_run_loop(libHandle, readCb, writeCb);
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
