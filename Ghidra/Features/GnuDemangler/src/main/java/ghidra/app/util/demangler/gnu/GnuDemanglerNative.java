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
package ghidra.app.util.demangler.gnu;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

/**
 * JNA interface for the GNU Demangler shared library.
 */
public interface GnuDemanglerNative extends Library {

    GnuDemanglerNative INSTANCE = Native.load("gnudemangler", GnuDemanglerNative.class);

    /**
     * Demangles a string using the GNU demangler.
     * 
     * @param mangled The mangled string.
     * @param options The demangling options.
     * @return A pointer to the demangled string, or NULL if demangling failed.
     *         The returned string must be freed using Native.free(Pointer.peer).
     */
    Pointer cplus_demangle(String mangled, int options);
}
