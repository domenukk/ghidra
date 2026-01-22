package ghidra.app.decompiler;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.PatchEncoder;
import ghidra.util.exception.NotFoundException;

public class DecompileProcessLib extends DecompileProcess {

    private Thread libThread;
    private long libHandle;
    private DecompilerNativeLib.ReadCallback readCb;
    private DecompilerNativeLib.WriteCallback writeCb;
    private PipedInputStream cppIn;
    private PipedOutputStream cppOut;
    private final DecompileCallbackProxy proxyCallback = new DecompileCallbackProxy();

    public DecompileProcessLib() {
        super("libdecomp");
    }

    @Override
    public synchronized void registerProgram(DecompileCallback cback, String pspecxml,
            String cspecxml, String tspecxml, String coretypesxml, ghidra.program.model.listing.Program program)
            throws IOException, DecompileException {

        // Update the delegate in the proxy
        proxyCallback.setDelegate(cback);

        super.registerProgram(cback, pspecxml, cspecxml, tspecxml, coretypesxml, program);
    }

    @Override
    protected void setup() throws IOException {
        if (getDisposeState() != DisposeState.NOT_DISPOSED) {
            throw new IOException("Decompiler has been disposed");
        }
        
        // Clean up any existing thread/streams
        if (libThread != null) {
            try {
                if (cppIn != null)
                    cppIn.close();
                if (cppOut != null)
                    cppOut.close();
            } catch (IOException e) {
                // ignore
            }
            libThread = null; // Thread should die on its own when streams close
        }

        // Initialize streams
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
        
        // Start the native loop thread
        libThread = new Thread(() -> {
            // Use the proxyCallback which delegates to the current 'cback'
            DecompilerNativeLib.ghidra_run_loop(libHandle, readCb, writeCb, proxyCallback);
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
        if (proxyCallback != null) {
            proxyCallback.setDelegate(null);
        }
    }

    /**
     * Proxy that delegates to the current DecompileCallback.
     * Use this to allow hot-swapping the callback instance for the long-running
     * native loop.
     */
    private static class DecompileCallbackProxy extends DecompileCallback {
        private volatile DecompileCallback delegate;

        public DecompileCallbackProxy() {
            super(); // Uses the protected no-arg constructor
        }

        void setDelegate(DecompileCallback delegate) {
            this.delegate = delegate;
        }

        private DecompileCallback getDelegate() {
            return delegate;
            // If delegate is null, we might NPE. But registerProgram sets it before
            // run_loop starts.
            // If disposed, it might be null.
        }

        @Override
        public void setFunction(Function func, Address entry, DecompileDebug dbg) {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.setFunction(func, entry, dbg);
        }

        @Override
        public String getNativeMessage() {
            DecompileCallback d = getDelegate();
            return (d != null) ? d.getNativeMessage() : null;
        }

        @Override
        void setNativeMessage(String msg) {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.setNativeMessage(msg);
        }

        @Override
        public byte[] getBytes(Address addr, int size) {
            DecompileCallback d = getDelegate();
            return (d != null) ? d.getBytes(addr, size) : null;
        }

        @Override
        public byte[] getBytes(long offset, String spaceName, int size) {
            DecompileCallback d = getDelegate();
            return (d != null) ? d.getBytes(offset, spaceName, size) : null;
        }

        @Override
        public void getComments(Address addr, int types, Encoder resultEncoder) throws IOException {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.getComments(addr, types, resultEncoder);
        }

        @Override
        public void getPcode(Address addr, PatchEncoder resultEncoder) {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.getPcode(addr, resultEncoder);
        }

        @Override
        public void getPcodeInject(String nm, Decoder paramDecoder, int type, Encoder resultEncoder)
                throws DecoderException, UnknownInstructionException, IOException, MemoryAccessException,
                NotFoundException {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.getPcodeInject(nm, paramDecoder, type, resultEncoder);
        }

        @Override
        public void getCPoolRef(long[] refs, Encoder resultEncoder) throws IOException {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.getCPoolRef(refs, resultEncoder);
        }

        @Override
        public String getCodeLabel(Address addr) throws IOException {
            DecompileCallback d = getDelegate();
            return (d != null) ? d.getCodeLabel(addr) : null;
        }

        @Override
        public boolean isNameUsed(String name, long startId, long stopId) {
            DecompileCallback d = getDelegate();
            return (d != null) ? d.isNameUsed(name, startId, stopId) : false;
        }

        @Override
        public void getNamespacePath(long id, Encoder resultEncoder) throws IOException {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.getNamespacePath(id, resultEncoder);
        }

        @Override
        public void getMappedSymbols(Address addr, Encoder resultEncoder) throws IOException {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.getMappedSymbols(addr, resultEncoder);
        }

        @Override
        public void getExternalRef(Address addr, Encoder resultEncoder) throws IOException {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.getExternalRef(addr, resultEncoder);
        }

        @Override
        public void getDataType(String name, long id, Encoder resultEncoder) throws IOException {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.getDataType(name, id, resultEncoder);
        }

        @Override
        public void getRegister(String name, Encoder resultEncoder) throws IOException {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.getRegister(name, resultEncoder);
        }

        @Override
        public String getRegisterName(Address addr, int size) {
            DecompileCallback d = getDelegate();
            return (d != null) ? d.getRegisterName(addr, size) : "";
        }

        @Override
        public void getTrackedRegisters(Address addr, Encoder resultEncoder) throws IOException {
            DecompileCallback d = getDelegate();
            if (d != null)
                d.getTrackedRegisters(addr, resultEncoder);
        }

        @Override
        public String getUserOpName(int index) {
            DecompileCallback d = getDelegate();
            return (d != null) ? d.getUserOpName(index) : null;
        }

        @Override
        public StringData getStringData(Address addr, int maxChars, String dtName, long dtId) {
            DecompileCallback d = getDelegate();
            return (d != null) ? d.getStringData(addr, maxChars, dtName, dtId) : null;
        }
    }
}
