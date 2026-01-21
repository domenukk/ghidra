package ghidra.app.decompiler;

import static org.junit.Assert.*;
import java.io.File;
import org.junit.Before;
import org.junit.Test;

public class DecompileLibTest {

    @org.junit.BeforeClass
    public static void setupClass() {
        System.setProperty("jna.debug_load", "true");
        System.setProperty("ghidra.decompiler.lib", "true");
        File libDir = new File("src/decompile/cpp");
        if (!libDir.exists()) {
             // Try full path if we are in root
             libDir = new File("Ghidra/Features/Decompiler/src/decompile/cpp");
        }
        // System.out.println("DEBUG: libDir=" + libDir.getAbsolutePath() + ", exists=" + libDir.exists());
        File libFile = new File(libDir, "libdecomp.so");
        // System.out.println("DEBUG: libFile=" + libFile.getAbsolutePath() + ", exists=" + libFile.exists());
        
        String currentPath = libDir.getAbsolutePath();
        String systemPaths = "/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:/usr/lib64:/lib64:/usr/lib:/lib";
        System.setProperty("jna.library.path", currentPath + File.pathSeparator + systemPaths);
        // System.out.println("DEBUG: jna.library.path=" + System.getProperty("jna.library.path"));
        try {
            System.load(libFile.getAbsolutePath());
            // System.out.println("DEBUG: System.load success");
        } catch (Throwable t) {
            // System.out.println("DEBUG: System.load failed: " + t);
            t.printStackTrace();
        }
    }

    @Test
    public void testFactoryReturnsLib() {
        DecompileProcess process = DecompileProcessFactory.get();
        assertTrue("Should return DecompileProcessLib", process instanceof DecompileProcessLib);
        process.dispose();
    }
    
    @Test
    public void testLibInitAndDispose() throws Exception {
        DecompileProcess process = DecompileProcessFactory.get();
        if (process instanceof DecompileProcessLib) {
            // We need to call setup() to initialize the library/thread.
            // setup() is protected, but we are in the same package.
            // However, setup() checks if exepath is set.
            // DecompileProcessLib might not need exepath, but the base class might check it?
            // DecompileProcessLib.setup() overrides it, so it should be fine.
            // But we can't call protected method from here if DecompileLibTest is in src/test/java
            // and DecompileProcess is in src/main/java?
            // Yes we can, if package name is same.
            
            // Reflection might be safer if visibility is an issue across source sets (though usually it's fine).
            java.lang.reflect.Method setupMethod = DecompileProcess.class.getDeclaredMethod("setup");
            setupMethod.setAccessible(true);
            setupMethod.invoke(process);
        }
        
        assertTrue("Process should be ready", process.isReady());
        process.dispose();
        assertFalse("Process should be disposed", process.isReady());
    }
}
