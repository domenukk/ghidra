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

    private DecompileCallback libCallback;

    @Override
    public synchronized void registerProgram(DecompileCallback cback, String pspecxml,
            String cspecxml, String tspecxml, String coretypesxml, ghidra.program.model.listing.Program program)
            throws IOException, DecompileException {
        libCallback = cback;
        super.registerProgram(cback, pspecxml, cspecxml, tspecxml, coretypesxml, program);
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
            // System.out.println("DEBUG: DecompileProcessLib calling ghidra_init");
            libHandle = DecompilerNativeLib.ghidra_init();
            // System.out.println("DEBUG: DecompileProcessLib ghidra_init returned " + libHandle);
        } catch (Throwable t) {
            // System.out.println("DEBUG: DecompileProcessLib ghidra_init failed: " + t);
            t.printStackTrace();
            throw new IOException("Failed to load decompiler library: " + t.getMessage(), t);
        }
        
        // Define callbacks
        readCb = (buf, len) -> {
            try {
                int n = cppIn.read(buf, 0, len);
                return (n < 0) ? 0 : n;
            } catch (IOException e) {
                return 0;
            }
        };
        
        writeCb = (buf, len) -> {
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
            // System.out.println("DEBUG: DecompileProcessLib thread starting ghidra_run_loop");
            int status = DecompilerNativeLib.ghidra_run_loop(libHandle, readCb, writeCb, libCallback);
            // System.out.println("DEBUG: DecompileProcessLib thread ghidra_run_loop returned " + status);
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
