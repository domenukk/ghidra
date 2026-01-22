package ghidra.app.decompiler;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

public class DecompileProcessLib extends DecompileProcess {

    private Thread libThread;

    // Streams from the "C++ side" perspective
    private PipedInputStream cSideIn; // C++ reads from this (Java writes to nativeOut -> cSideIn)
    private PipedOutputStream cSideOut; // C++ writes to this (Java reads from nativeIn <- cSideOut)

    public DecompileProcessLib() {
        super("libdecomp");
    }

    @Override
    protected void setup() throws IOException {
        if (getDisposeState() != DisposeState.NOT_DISPOSED) {
            throw new IOException("Decompiler has been disposed");
        }
        
        // Clean up any existing thread/streams
        disposeImpl();

        // 1. Java -> C++ (Java writes to nativeOut, C++ reads from cSideIn)
        cSideIn = new PipedInputStream(4096 * 16);
        this.nativeOut = new PipedOutputStream(cSideIn);

        // 2. C++ -> Java (C++ writes to cSideOut, Java reads from nativeIn)
        PipedInputStream javaIn = new PipedInputStream(4096 * 16);
        this.nativeIn = javaIn;
        cSideOut = new PipedOutputStream(javaIn);
        
        // Load library if needed
        long libHandle = 0;
        try {
            libHandle = DecompilerNativeLib.ghidra_init();
        } catch (Throwable t) {
            t.printStackTrace();
            throw new IOException("Failed to load decompiler library: " + t.getMessage(), t);
        }
        
        final long finalHandle = libHandle;

        // Callbacks
        DecompilerNativeLib.ReadCallback readCb = (buf, len) -> {
            try {
                // Ensure we read 'len' bytes or as much as available?
                // The C++ side expects 'len' bytes usually, or standard read semantics.
                // PipedInputStream.read(buf, off, len) returns bytes read.
                int read = cSideIn.read(buf, 0, len);
                return (read < 0) ? 0 : read; // Return 0 on EOF for C++ handling? Or let it return 0.
            } catch (IOException e) {
                return 0;
            }
        };
        
        DecompilerNativeLib.WriteCallback writeCb = (buf, len) -> {
            try {
                cSideOut.write(buf, 0, len);
                cSideOut.flush();
                return len;
            } catch (IOException e) {
                return 0;
            }
        };
        
        // Start the native loop thread
        libThread = new Thread(() -> {
            // Pass null for DecompileCallback as we are using stream mode
            DecompilerNativeLib.ghidra_run_loop(finalHandle, readCb, writeCb, null);
        }, "DecompilerLibThread");
        libThread.setDaemon(true);
        libThread.start();
        
        statusGood = true;
    }
    
    @Override
    public void dispose() {
        super.dispose();
        disposeImpl();
    }

    private void disposeImpl() {
        try {
            if (cSideIn != null)
                cSideIn.close();
            if (cSideOut != null)
                cSideOut.close();
        } catch (IOException e) {
            // ignore
        }
        libThread = null;
    }
}
