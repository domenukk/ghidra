#include <jni.h>
#include <iostream>
#include <streambuf>
#include <vector>
#include <cstring>
#include "ghidra_arch.hh"
#include "loadimage.hh"
#include "ghidra_process.hh"

using namespace ghidra;
using namespace std;

#include <mutex>
// Mutex removed to allow parallel decompilation
// static std::mutex global_run_mutex;

thread_local jobject current_callback = nullptr;
thread_local JNIEnv* current_env = nullptr;

// JNI Stream Buffer (unchanged)
class JNIStreambuf : public std::streambuf {
    JNIEnv *env;
    jobject read_cb;
    jobject write_cb;
    jmethodID read_mid;
    jmethodID write_mid;
    std::vector<char> buffer;
    jbyteArray java_buffer; // Reusable buffer

public:
    JNIStreambuf(JNIEnv *env, jobject r_cb, jobject w_cb) 
        : env(env), buffer(4096), java_buffer(nullptr) {
        
        // Create GlobalRefs for callbacks
        read_cb = env->NewGlobalRef(r_cb);
        write_cb = env->NewGlobalRef(w_cb);
        
        setg(buffer.data(), buffer.data(), buffer.data());
        setp(buffer.data(), buffer.data() + buffer.size());
        
        jclass read_cls = env->GetObjectClass(read_cb);
        read_mid = env->GetMethodID(read_cls, "invoke", "([BI)I");
        env->DeleteLocalRef(read_cls);
        if (!read_mid) {
            FILE *f = fopen("/tmp/ghidra_debug.log", "a");
            if (f) { fprintf(f, "ERROR: GetMethodID for read_cb failed\n"); fclose(f); }
            return; // Or throw
        }
        
        jclass write_cls = env->GetObjectClass(write_cb);
        write_mid = env->GetMethodID(write_cls, "invoke", "([BI)I");
        env->DeleteLocalRef(write_cls);
        if (!write_mid) {
            FILE *f = fopen("/tmp/ghidra_debug.log", "a");
            if (f) { fprintf(f, "ERROR: GetMethodID for write_cb failed\n"); fclose(f); }
            return; // Or throw
        }

        // Allocate reusable buffer
        jbyteArray local_buf = env->NewByteArray(buffer.size());
        if (local_buf) {
            java_buffer = (jbyteArray)env->NewGlobalRef(local_buf);
            env->DeleteLocalRef(local_buf);
        }
        
        
    }

    virtual ~JNIStreambuf() {
        sync();
        if (java_buffer) env->DeleteGlobalRef(java_buffer);
        if (read_cb) env->DeleteGlobalRef(read_cb);
        if (write_cb) env->DeleteGlobalRef(write_cb);
    }

protected:
    virtual int_type underflow() override {
        
        
        // Use thread-local env if available and different, to avoid cross-thread JNI usage
        JNIEnv* effective_env = env;
        if (current_env && current_env != env) {
             
             effective_env = current_env;
        }

        if (!java_buffer) return traits_type::eof();

        FILE *f = fopen("/tmp/ghidra_debug.log", "a");
        if (f) { fprintf(f, "DEBUG: underflow calling read_cb\n"); fclose(f); }

        int bytes_read = effective_env->CallIntMethod(read_cb, read_mid, java_buffer, (jint)buffer.size());
        
        FILE *f2 = fopen("/tmp/ghidra_debug.log", "a");
        if (f2) { fprintf(f2, "DEBUG: underflow read_cb returned: %d\n", bytes_read); fclose(f2); }

        if (effective_env->ExceptionCheck()) {
            
            effective_env->ExceptionDescribe();
            effective_env->ExceptionClear();
            return traits_type::eof();
        }
        
        if (bytes_read <= 0) {
            return traits_type::eof();
        }
        
        if (bytes_read > (int)buffer.size()) bytes_read = buffer.size();

        // Debug prints
        

        effective_env->GetByteArrayRegion(java_buffer, 0, bytes_read, (jbyte*)buffer.data());
        
        if (effective_env->ExceptionCheck()) {
             
             effective_env->ExceptionDescribe();
             effective_env->ExceptionClear();
             return traits_type::eof();
        }
        
        
        setg(buffer.data(), buffer.data(), buffer.data() + bytes_read);
        
        return traits_type::to_int_type(*gptr());
    }

    virtual int_type overflow(int_type c) override {
        // Sync first to make space
        if (sync() == -1) return traits_type::eof();
        
        if (c != traits_type::eof()) {
            if (pptr() < epptr()) {
                *pptr() = (char)c;
                pbump(1);
            } else {
                // Buffer size is 0 or internal error
                return traits_type::eof();
            }
        }
        return c;
    }

    virtual int sync() override {
        
        
        JNIEnv* effective_env = env;
        if (current_env && current_env != env) {
             effective_env = current_env;
        }

        std::ptrdiff_t n = pptr() - pbase();
        if (n > 0) {
            if (!java_buffer) return -1;

            effective_env->SetByteArrayRegion(java_buffer, 0, (jsize)n, (const jbyte*)pbase());
            effective_env->CallIntMethod(write_cb, write_mid, java_buffer, (jint)n);
            
            if (effective_env->ExceptionCheck()) {
                
                effective_env->ExceptionDescribe();
                effective_env->ExceptionClear();
                return -1;
            }

            pbump(-(int)n);
        }
        return 0;
    }

    virtual std::streamsize xsputn(const char* s, std::streamsize n) override {
        if (sync() == -1) return 0;
        
        if (!java_buffer) return 0;

        JNIEnv* effective_env = env;
        if (current_env && current_env != env) {
             effective_env = current_env;
        }

        std::streamsize remaining = n;
        const char* p = s;
        while (remaining > 0) {
            std::streamsize chunk = remaining;
            if (chunk > (std::streamsize)buffer.size()) chunk = buffer.size();
            
            effective_env->SetByteArrayRegion(java_buffer, 0, (jsize)chunk, (const jbyte*)p);
            effective_env->CallIntMethod(write_cb, write_mid, java_buffer, (jint)chunk);
            
            if (effective_env->ExceptionCheck()) {
                effective_env->ExceptionDescribe();
                effective_env->ExceptionClear();
                return n - remaining;
            }

            p += chunk;
            remaining -= chunk;
        }
        return n;
    }
};

// Thread-local storage for the callback


// JNI LoadImage Implementation
class JNICallbackLoadImage : public LoadImage {
public:
    JNICallbackLoadImage(const string &f) : LoadImage(f) {}
    
    virtual void loadFill(uint1 *ptr, int4 size, const Address &addr) {
        if (!current_env || !current_callback) {
            memset(ptr, 0, size);
            return;
        }

        jclass cls = current_env->GetObjectClass(current_callback);
        // getBytes(long offset, String spaceName, int size) -> byte[]
        jmethodID mid = current_env->GetMethodID(cls, "getBytes", "(JLjava/lang/String;I)[B");
        if (!mid) {
            current_env->ExceptionClear();
            memset(ptr, 0, size);
            return;
        }
        
        jlong offset = (jlong)addr.getOffset();
        jstring spaceName = current_env->NewStringUTF(addr.getSpace()->getName().c_str());
        jint jsize = (jint)size;
        
        jbyteArray jbytes = (jbyteArray)current_env->CallObjectMethod(current_callback, mid, offset, spaceName, jsize);
        
        current_env->DeleteLocalRef(spaceName);
        
        if (current_env->ExceptionCheck()) {
            current_env->ExceptionDescribe();
            current_env->ExceptionClear();
            memset(ptr, 0, size);
            return;
        }
        
        if (jbytes == nullptr) {
            // DataUnavailError
            throw DataUnavailError("Data unavailable");
        }
        
        jint len = current_env->GetArrayLength(jbytes);
        if (len > 0) {
            int copy_len = (len < size) ? len : size;
            current_env->GetByteArrayRegion(jbytes, 0, copy_len, (jbyte*)ptr);
            if (copy_len < size) {
                memset(ptr + copy_len, 0, size - copy_len);
            }
        } else {
            memset(ptr, 0, size);
        }
        
        current_env->DeleteLocalRef(jbytes);
        current_env->DeleteLocalRef(cls);
    }
    
    virtual string getArchType(void) const { return "jni_callback"; }
    virtual void adjustVma(long adjust) {}
};

// Custom Architecture to use JNICallbackLoadImage
class ArchitectureGhidraJNI : public ArchitectureGhidra {
public:
    ArchitectureGhidraJNI(const string &pspec, const string &cspec, const string &tspec, const string &corespec,
                          istream &i, ostream &o)
        : ArchitectureGhidra(pspec, cspec, tspec, corespec, i, o) {}

    virtual void buildLoader(DocumentStorage &store) {
        loader = new JNICallbackLoadImage("jni_loader");
    }
};

// Custom RegisterProgram to use ArchitectureGhidraJNI
class RegisterProgramJNI : public RegisterProgram {
protected:
    virtual ArchitectureGhidra *createArchitecture(const string &pspec,const string &cspec,const string &tspec,const string &corespec,istream &sin,ostream &sout) {
        return new ArchitectureGhidraJNI(pspec,cspec,tspec,corespec,sin,sout);
    }
};



extern "C" {

JNIEXPORT jlong JNICALL Java_ghidra_app_decompiler_DecompilerNativeLib_ghidra_1init
  (JNIEnv *env, jclass cls) {
    static std::mutex init_mutex;
    std::lock_guard<std::mutex> lock(init_mutex);

    static bool initialized = false;
    if (initialized) {
        return (jlong)1;
    }
    

    AttributeId::initialize();
    ElementId::initialize();
    
    CapabilityPoint::initializeAll();
    
    // Register our custom command
    
    GhidraCapability::registerCommand("registerProgram", new RegisterProgramJNI());
    
    initialized = true;
    return (jlong)1;
}



JNIEXPORT jint JNICALL Java_ghidra_app_decompiler_DecompilerNativeLib_ghidra_1run_1loop
  (JNIEnv *env, jclass cls, jlong handle, jobject read_cb, jobject write_cb, jobject callback) {

    // RAII class to manage current_env and current_callback
    class EnvRestorer {
        JNIEnv*& target_env;
        jobject& target_cb;
        JNIEnv* prev_env;
        jobject prev_cb;
    public:
        EnvRestorer(JNIEnv*& env_var, jobject& cb_var, JNIEnv* new_env, jobject new_cb)
            : target_env(env_var), target_cb(cb_var), prev_env(env_var), prev_cb(cb_var) {
            target_env = new_env;
            target_cb = new_cb;
            
        }
        ~EnvRestorer() {
            
            target_env = prev_env;
            target_cb = prev_cb;
        }
    };

    // std::lock_guard<std::mutex> lock(global_run_mutex);
    
    EnvRestorer restorer(current_env, current_callback, env, callback);
    
    JNIStreambuf in_buf(env, read_cb, write_cb);
    JNIStreambuf out_buf(env, read_cb, write_cb);
    istream in_stream(&in_buf);
    ostream out_stream(&out_buf);
    
    int4 status = 0;
    try {
        while(status == 0) {
            status = GhidraCapability::readCommand(in_stream, out_stream);
        }
    } catch (const std::exception& e) {
        status = -1;
    } catch (...) {
        status = -1;
    }
    
    return status;
}

JNIEXPORT void JNICALL Java_ghidra_app_decompiler_DecompilerNativeLib_ghidra_1cleanup
  (JNIEnv *env, jclass cls, jlong handle) {
    GhidraCapability::shutDown();
}

}
