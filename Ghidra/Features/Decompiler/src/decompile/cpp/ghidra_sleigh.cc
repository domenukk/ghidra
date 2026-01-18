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

#include "sleigh.hh"
#include "loadimage.hh"
#include "emulate.hh"
#include "xml.hh"
#include <iostream>
#include <vector>
#include <cstring>

using namespace ghidra;
using namespace std;

extern "C" {

// Callback definitions
typedef int (*ReadBytesCallback)(void* user_data, uint64_t addr, void* buf, int len);
typedef void (*AssemblyCallback)(void* user_data, uint64_t addr, const char* mnem, const char* body);
typedef void (*PcodeCallback)(void* user_data, uint64_t addr, int opcode, void* out_var, void* in_vars, int isize);

// C-compatible VarnodeData
struct C_VarnodeData {
    const char* space_name;
    uint64_t offset;
    uint32_t size;
};

// Helper classes
class CallbackLoadImage : public LoadImage {
    ReadBytesCallback cb;
    void* user_data;
public:
    CallbackLoadImage(ReadBytesCallback cb, void* user_data) : LoadImage("callback"), cb(cb), user_data(user_data) {}
    virtual void loadFill(uint1 *ptr, int4 size, const Address &addr) {
        int result = cb(user_data, addr.getOffset(), ptr, size);
        if (result < size) {
            // Fill the rest with zeros if read is partial
            if (result < 0) result = 0;
            memset(ptr + result, 0, size - result);
        }
    }
    virtual string getArchType(void) const { return "callback"; }
    virtual void adjustVma(long adjust) {}
};

class CallbackAssemblyEmit : public AssemblyEmit {
    AssemblyCallback cb;
    void* user_data;
public:
    CallbackAssemblyEmit(AssemblyCallback cb, void* user_data) : cb(cb), user_data(user_data) {}
    virtual void dump(const Address &addr, const string &mnem, const string &body) {
        cb(user_data, addr.getOffset(), mnem.c_str(), body.c_str());
    }
};

class CallbackPcodeEmit : public PcodeEmit {
    PcodeCallback cb;
    void* user_data;
public:
    CallbackPcodeEmit(PcodeCallback cb, void* user_data) : cb(cb), user_data(user_data) {}
    
    void convertVarnode(const VarnodeData& vn, C_VarnodeData& cvn) {
        cvn.space_name = vn.space ? vn.space->getName().c_str() : "null";
        cvn.offset = vn.offset;
        cvn.size = vn.size;
    }

    virtual void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) {
        C_VarnodeData c_out;
        C_VarnodeData* c_out_ptr = nullptr;
        
        if (outvar) {
            convertVarnode(*outvar, c_out);
            c_out_ptr = &c_out;
        }
        
        vector<C_VarnodeData> c_vars(isize);
        for(int i=0; i<isize; ++i) {
            convertVarnode(vars[i], c_vars[i]);
        }
        
        cb(user_data, addr.getOffset(), opc, c_out_ptr, c_vars.data(), isize);
    }
};

struct SleighInstance {
    CallbackLoadImage* loader;
    ContextInternal* context;
    Sleigh* sleigh;
    
    SleighInstance(ReadBytesCallback read_cb, void* user_data) {
        loader = new CallbackLoadImage(read_cb, user_data);
        context = new ContextInternal();
        sleigh = new Sleigh(loader, context);
    }
    
    ~SleighInstance() {
        delete sleigh;
        delete context;
        delete loader;
    }
};

// Exported functions
void* Ghidra_Sleigh_create(ReadBytesCallback read_cb, void* user_data) {
    return new SleighInstance(read_cb, user_data);
}

void Ghidra_Sleigh_destroy(void* instance) {
    if (instance) {
        delete (SleighInstance*)instance;
    }
}

int Ghidra_Sleigh_initialize(void* instance, const char* sla_path) {
    SleighInstance* si = (SleighInstance*)instance;
    cerr << "Entering Ghidra_Sleigh_initialize" << endl;
    if (!si) {
        cerr << "Instance is null" << endl;
        return 0;
    }
    if (!sla_path) {
        cerr << "sla_path is null" << endl;
        return 0;
    }
    cerr << "sla_path: " << (void*)sla_path << " string: " << sla_path << endl;
    
    try {

        cerr << "Initializing sleigh with file: " << sla_path << endl;
        si->sleigh->initialize(string(sla_path));
        cerr << "Sleigh initialized" << endl;
        return 1; // Success
    } catch (LowlevelError &e) {
        cerr << "Sleigh Error: " << e.explain << endl;
        return 0;
    } catch (DecoderError &e) {
        cerr << "Sleigh Decoder Error: " << e.explain << endl;
        return 0;
    } catch (exception &e) {
        cerr << "Sleigh Exception: " << e.what() << endl;
        return 0;
    } catch (const char* e) {
        cerr << "Sleigh String Error: " << e << endl;
        return 0;
    } catch (string &e) {
        cerr << "Sleigh String Error: " << e << endl;
        return 0;
    } catch (...) {
        cerr << "Sleigh Unknown Error" << endl;
        return 0;
    }
}

int Ghidra_Sleigh_disassemble(void* instance, uint64_t addr, AssemblyCallback cb, void* user_data) {
    SleighInstance* si = (SleighInstance*)instance;
    try {
        Address address(si->sleigh->getDefaultCodeSpace(), addr);
        CallbackAssemblyEmit emit(cb, user_data);
        return si->sleigh->printAssembly(emit, address);
    } catch (...) {
        return 0;
    }
}

int Ghidra_Sleigh_oneInstruction(void* instance, uint64_t addr, PcodeCallback cb, void* user_data) {
    SleighInstance* si = (SleighInstance*)instance;
    try {
        Address address(si->sleigh->getDefaultCodeSpace(), addr);
        CallbackPcodeEmit emit(cb, user_data);
        return si->sleigh->oneInstruction(emit, address);
    } catch (...) {
        return 0;
    }
}

const char* Ghidra_Sleigh_getVersion() {
    return "1.0";
}

}
