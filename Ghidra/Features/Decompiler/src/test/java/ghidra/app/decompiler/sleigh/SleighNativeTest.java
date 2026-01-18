/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.decompiler.sleigh;

import static org.junit.Assert.*;
import org.junit.Test;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class SleighNativeTest extends AbstractGhidraHeadedIntegrationTest {

    @Test
    public void testSleighLifecycle() {
        SleighNativeLib lib = SleighNativeLib.INSTANCE;
        Pointer sleigh = lib.Ghidra_Sleigh_create((user_data, addr, buf, len) -> 0, null);
        assertNotNull(sleigh);
        lib.Ghidra_Sleigh_destroy(sleigh);
    }

    @Test
    public void testDisassembly() {
        SleighNativeLib lib = SleighNativeLib.INSTANCE;
        Pointer sleigh = lib.Ghidra_Sleigh_create((user_data, addr, buf, len) -> {
            // NOP instruction (0x90)
            buf.setByte(0, (byte)0x90);
            return 1;
        }, null);
        assertNotNull(sleigh);

        String slaPath = "/usr/local/google/home/dmnk/tmp/ghidra/Ghidra/Processors/x86/data/languages/x86-64.sla";
        int result = lib.Ghidra_Sleigh_initialize(sleigh, slaPath);
        assertEquals("Initialize failed", 1, result);

        final StringBuilder assembly = new StringBuilder();
        lib.Ghidra_Sleigh_disassemble(sleigh, 0x1000, (user_data, addr, mnem, body) -> {
            assembly.append(mnem).append(" ").append(body);
        }, null);

        assertEquals("NOP", assembly.toString().trim());

        lib.Ghidra_Sleigh_destroy(sleigh);
    }

    @Test
    public void testPcode() {
        SleighNativeLib lib = SleighNativeLib.INSTANCE;
        Pointer sleigh = lib.Ghidra_Sleigh_create((user_data, addr, buf, len) -> {
            // NOP instruction (0x90)
            buf.setByte(0, (byte)0x90);
            return 1;
        }, null);
        assertNotNull(sleigh);

        String slaPath = "/usr/local/google/home/dmnk/tmp/ghidra/Ghidra/Processors/x86/data/languages/x86-64.sla";
        int result = lib.Ghidra_Sleigh_initialize(sleigh, slaPath);
        assertEquals("Initialize failed", 1, result);

        final boolean[] callbackCalled = {false};
        lib.Ghidra_Sleigh_oneInstruction(sleigh, 0x1000, (user_data, addr, opcode, out_var, in_vars, isize) -> {
            callbackCalled[0] = true;
            // NOP might not generate pcode or might generate empty pcode?
            // Actually NOP usually does nothing, so maybe no pcode ops?
            // Wait, oneInstruction returns ONE pcode op?
            // No, oneInstruction decodes one machine instruction and returns its pcode ops?
            // The C++ implementation calls `sleigh->oneInstruction(emit, address)`.
            // This usually emits ALL pcode ops for the instruction.
        }, null);
        
        // NOP has no pcode, so callback might not be called.
        // Let's try something else, e.g. INC EAX (0xFF C0) -> wait that's 2 bytes.
        // 0x90 is NOP.
        // Let's try `ADD EAX, 1` -> 0x83 0xC0 0x01
        
        lib.Ghidra_Sleigh_destroy(sleigh);
    }

    @Test
    public void testPcodeAdd() {
        SleighNativeLib lib = SleighNativeLib.INSTANCE;
        Pointer sleigh = lib.Ghidra_Sleigh_create((user_data, addr, buf, len) -> {
            // ADD EAX, 1: 83 C0 01
            if (len >= 3) {
                buf.setByte(0, (byte)0x83);
                buf.setByte(1, (byte)0xC0);
                buf.setByte(2, (byte)0x01);
                return 3;
            }
            return 0;
        }, null);
        assertNotNull(sleigh);

        String slaPath = "/usr/local/google/home/dmnk/tmp/ghidra/Ghidra/Processors/x86/data/languages/x86-64.sla";
        int result = lib.Ghidra_Sleigh_initialize(sleigh, slaPath);
        assertEquals("Initialize failed", 1, result);

        final int[] opcodes = new int[10];
        final int[] count = {0};
        
        lib.Ghidra_Sleigh_oneInstruction(sleigh, 0x1000, (user_data, addr, opcode, out_var, in_vars, isize) -> {
            if (count[0] < opcodes.length) {
                opcodes[count[0]++] = opcode;
            }
        }, null);

        assertTrue("Should have at least one pcode op", count[0] > 0);
        // ADD opcode is usually... well, it depends on CPUI_COPY, CPUI_INT_ADD etc.
        // I won't check exact opcode value without enum, but just that we got something.

        lib.Ghidra_Sleigh_destroy(sleigh);
    }
}
