#include <jni.h>
#include "ghidra_process.hh"
#include <streambuf>
#include <iostream>
#include <vector>
#include <cstring>

using namespace ghidra;
using namespace std;

extern "C" {

class JNIStreambuf : public std::streambuf {
    JNIEnv* env;
    jobject read_cb;
    jobject write_cb;
    char in_buf[4096];
    char out_buf[4096];

protected:
    virtual int underflow() {
        if (gptr() < egptr()) return traits_type::to_int_type(*gptr());
        
        jclass cls = env->GetObjectClass(read_cb);
        jmethodID mid = env->GetMethodID(cls, "invoke", "([BI)I");
        if (!mid) return traits_type::eof();
        
        jbyteArray jbuf = env->NewByteArray(sizeof(in_buf));
        int n = env->CallIntMethod(read_cb, mid, jbuf, (jint)sizeof(in_buf));
        
        if (n <= 0) {
            env->DeleteLocalRef(jbuf);
            env->DeleteLocalRef(cls);
            return traits_type::eof();
        }
        
        env->GetByteArrayRegion(jbuf, 0, n, (jbyte*)in_buf);
        env->DeleteLocalRef(jbuf);
        env->DeleteLocalRef(cls);
        
        setg(in_buf, in_buf, in_buf + n);
        return traits_type::to_int_type(*gptr());
    }

    virtual int overflow(int c) {
        if (c != traits_type::eof()) {
            *pptr() = c;
            pbump(1);
        }
        if (flush_buffer() == -1) return traits_type::eof();
        return c == traits_type::eof() ? traits_type::not_eof(c) : c;
    }

    virtual int sync() {
        return flush_buffer();
    }

    int flush_buffer() {
        int n = pptr() - pbase();
        if (n > 0) {
            jclass cls = env->GetObjectClass(write_cb);
            jmethodID mid = env->GetMethodID(cls, "invoke", "([BI)I");
            if (!mid) return -1;

            jbyteArray jbuf = env->NewByteArray(n);
            env->SetByteArrayRegion(jbuf, 0, n, (jbyte*)out_buf);
            
            int written = env->CallIntMethod(write_cb, mid, jbuf, n);
            env->DeleteLocalRef(jbuf);
            env->DeleteLocalRef(cls);
            
            if (written != n) return -1;
            pbump(-n);
        }
        return 0;
    }

public:
    JNIStreambuf(JNIEnv* e, jobject r, jobject w) : env(e), read_cb(r), write_cb(w) {
        setg(in_buf, in_buf, in_buf);
        setp(out_buf, out_buf + sizeof(out_buf));
    }
    
    ~JNIStreambuf() {
        sync();
    }
};

JNIEXPORT jlong JNICALL Java_ghidra_app_decompiler_DecompilerNativeLib_ghidra_1init
  (JNIEnv *env, jclass cls) {
    printf("JNI Decompiler Initialized!\n");
    fflush(stdout);
    AttributeId::initialize();
    ElementId::initialize();
    CapabilityPoint::initializeAll();
    return (jlong)1;
}

JNIEXPORT jint JNICALL Java_ghidra_app_decompiler_DecompilerNativeLib_ghidra_1run_1loop
  (JNIEnv *env, jclass cls, jlong handle, jobject read_cb, jobject write_cb) {
    
    JNIStreambuf buf(env, read_cb, write_cb);
    istream sin(&buf);
    ostream sout(&buf);
    
    int status = 0;
    while(status == 0) {
        if (sin.peek() == EOF) {
            break;
        }
        try {
            status = GhidraCapability::readCommand(sin, sout);
        } catch (...) {
            status = 1;
        }
        sout.flush();
    }
    return status;
}

JNIEXPORT void JNICALL Java_ghidra_app_decompiler_DecompilerNativeLib_ghidra_1cleanup
  (JNIEnv *env, jclass cls, jlong handle) {
    GhidraCapability::shutDown();
}

}
