package ghidra.app.decompiler;

import static org.junit.Assert.*;
import org.junit.Test;

public class DecompileLibTest {

    @org.junit.BeforeClass
    public static void setupClass() {
        System.setProperty("ghidra.decompiler.lib", "true");
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
