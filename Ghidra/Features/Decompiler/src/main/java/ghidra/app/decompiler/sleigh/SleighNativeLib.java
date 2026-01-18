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

import com.sun.jna.Callback;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

public interface SleighNativeLib extends Library {
    SleighNativeLib INSTANCE = Native.load("sla", SleighNativeLib.class);

    String Ghidra_Sleigh_getVersion();

    Pointer Ghidra_Sleigh_create(ReadBytesCallback read_cb, Pointer user_data);
    void Ghidra_Sleigh_destroy(Pointer sleigh);
    int Ghidra_Sleigh_initialize(Pointer sleigh, String sla_path);
    int Ghidra_Sleigh_disassemble(Pointer sleigh, long addr, AssemblyCallback cb, Pointer user_data);
    int Ghidra_Sleigh_oneInstruction(Pointer sleigh, long addr, PcodeCallback cb, Pointer user_data);

    interface ReadBytesCallback extends Callback {
        int invoke(Pointer user_data, long addr, Pointer buf, int len);
    }

    interface AssemblyCallback extends Callback {
        void invoke(Pointer user_data, long addr, String mnem, String body);
    }

    interface PcodeCallback extends Callback {
        void invoke(Pointer user_data, long addr, int opcode, VarnodeData out_var, Pointer in_vars, int isize);
    }

    @Structure.FieldOrder({"space_name", "offset", "size"})
    class VarnodeData extends Structure {
        public String space_name;
        public long offset;
        public int size;

        public static class ByReference extends VarnodeData implements Structure.ByReference {}
        public static class ByValue extends VarnodeData implements Structure.ByValue {}
    }
}
