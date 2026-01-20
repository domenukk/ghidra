#include <jni.h>
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

// Helper classes
class JNICallbackLoadImage : public LoadImage {
    jobject callback;
    JNIEnv* current_env;
public:
    JNICallbackLoadImage(jobject callback) : LoadImage("jni_callback"), callback(callback), current_env(nullptr) {}
    
    void setEnv(JNIEnv* env) { current_env = env; }

    virtual void loadFill(uint1 *ptr, int4 size, const Address &addr) {
        if (!current_env) return;
        
        jbyteArray buf = current_env->NewByteArray(size);
        jclass cls = current_env->GetObjectClass(callback);
        jmethodID mid = current_env->GetMethodID(cls, "invoke", "(J[BI)I");
        
        int result = current_env->CallIntMethod(callback, mid, (jlong)addr.getOffset(), buf, size);
        
        if (result > 0) {
            current_env->GetByteArrayRegion(buf, 0, result, (jbyte*)ptr);
            if (result < size) {
                memset(ptr + result, 0, size - result);
            }
        } else {
            memset(ptr, 0, size);
        }
        current_env->DeleteLocalRef(buf);
        current_env->DeleteLocalRef(cls);
    }
    
    virtual string getArchType(void) const { return "jni_callback"; }
    virtual void adjustVma(long adjust) {}
};

class JNICallbackAssemblyEmit : public AssemblyEmit {
    JNIEnv* env;
    jobject callback;
public:
    JNICallbackAssemblyEmit(JNIEnv* env, jobject callback) : env(env), callback(callback) {}
    
    virtual void dump(const Address &addr, const string &mnem, const string &body) {
        jstring jmnem = env->NewStringUTF(mnem.c_str());
        jstring jbody = env->NewStringUTF(body.c_str());
        
        jclass cls = env->GetObjectClass(callback);
        jmethodID mid = env->GetMethodID(cls, "invoke", "(JLjava/lang/String;Ljava/lang/String;)V");
        
        env->CallVoidMethod(callback, mid, (jlong)addr.getOffset(), jmnem, jbody);
        
        env->DeleteLocalRef(jmnem);
        env->DeleteLocalRef(jbody);
        env->DeleteLocalRef(cls);
    }
};

class JNICallbackPcodeEmit : public PcodeEmit {
    JNIEnv* env;
    jobject callback;
    jclass varnodeClass;
    jmethodID varnodeCtor;
public:
    JNICallbackPcodeEmit(JNIEnv* env, jobject callback) : env(env), callback(callback) {
        jclass localCls = env->FindClass("ghidra/app/decompiler/sleigh/SleighNativeLib$VarnodeData");
        varnodeClass = (jclass)env->NewLocalRef(localCls); // Keep it local, but valid for this scope
        varnodeCtor = env->GetMethodID(varnodeClass, "<init>", "(Ljava/lang/String;JI)V");
        env->DeleteLocalRef(localCls);
    }
    
    jobject createVarnodeData(const VarnodeData& vn) {
        const char* spaceName = vn.space ? vn.space->getName().c_str() : "null";
        jstring jSpaceName = env->NewStringUTF(spaceName);
        jobject jVn = env->NewObject(varnodeClass, varnodeCtor, jSpaceName, (jlong)vn.offset, (jint)vn.size);
        env->DeleteLocalRef(jSpaceName);
        return jVn;
    }

    virtual void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) {
        jobject jOutVar = nullptr;
        if (outvar) {
            jOutVar = createVarnodeData(*outvar);
        }
        
        jobjectArray jInVars = env->NewObjectArray(isize, varnodeClass, nullptr);
        for(int i=0; i<isize; ++i) {
            jobject jVar = createVarnodeData(vars[i]);
            env->SetObjectArrayElement(jInVars, i, jVar);
            env->DeleteLocalRef(jVar);
        }
        
        jclass cls = env->GetObjectClass(callback);
        jmethodID mid = env->GetMethodID(cls, "invoke", "(JILghidra/app/decompiler/sleigh/SleighNativeLib$VarnodeData;[Lghidra/app/decompiler/sleigh/SleighNativeLib$VarnodeData;I)V");
        
        env->CallVoidMethod(callback, mid, (jlong)addr.getOffset(), (jint)opc, jOutVar, jInVars, (jint)isize);
        
        if (jOutVar) env->DeleteLocalRef(jOutVar);
        env->DeleteLocalRef(jInVars);
        env->DeleteLocalRef(cls);
    }
};

struct SleighInstance {
    JNICallbackLoadImage* loader;
    ContextInternal* context;
    Sleigh* sleigh;
    jobject read_cb_ref;
    
    SleighInstance(JNIEnv* env, jobject read_cb) {
        read_cb_ref = env->NewGlobalRef(read_cb);
        loader = new JNICallbackLoadImage(read_cb_ref);
        context = new ContextInternal();
        sleigh = new Sleigh(loader, context);
    }
    
    ~SleighInstance() {
        delete sleigh;
        delete context;
        delete loader;
        // Note: We can't DeleteGlobalRef here because we don't have JNIEnv.
        // It must be done in destroy()
    }
};

JNIEXPORT jstring JNICALL Java_ghidra_app_decompiler_sleigh_SleighNativeLib_getVersion
  (JNIEnv *env, jclass cls) {
    return env->NewStringUTF("1.0");
}

JNIEXPORT jlong JNICALL Java_ghidra_app_decompiler_sleigh_SleighNativeLib_create
  (JNIEnv *env, jclass cls, jobject read_cb) {
    return (jlong) new SleighInstance(env, read_cb);
}

JNIEXPORT void JNICALL Java_ghidra_app_decompiler_sleigh_SleighNativeLib_destroy
  (JNIEnv *env, jclass cls, jlong sleigh_ptr) {
    SleighInstance* si = (SleighInstance*)sleigh_ptr;
    if (si) {
        env->DeleteGlobalRef(si->read_cb_ref);
        delete si;
    }
}

JNIEXPORT jint JNICALL Java_ghidra_app_decompiler_sleigh_SleighNativeLib_initialize
  (JNIEnv *env, jclass cls, jlong sleigh_ptr, jstring sla_path) {
    SleighInstance* si = (SleighInstance*)sleigh_ptr;
    if (!si) return 0;
    
    const char* path = env->GetStringUTFChars(sla_path, 0);
    int result = 0;
    try {
        si->sleigh->initialize(string(path));
        result = 1;
    } catch (...) {
        result = 0;
    }
    env->ReleaseStringUTFChars(sla_path, path);
    return result;
}

JNIEXPORT jint JNICALL Java_ghidra_app_decompiler_sleigh_SleighNativeLib_disassemble
  (JNIEnv *env, jclass cls, jlong sleigh_ptr, jlong addr, jobject cb) {
    SleighInstance* si = (SleighInstance*)sleigh_ptr;
    if (!si) return 0;
    
    si->loader->setEnv(env);
    try {
        Address address(si->sleigh->getDefaultCodeSpace(), (uint64_t)addr);
        JNICallbackAssemblyEmit emit(env, cb);
        int len = si->sleigh->printAssembly(emit, address);
        si->loader->setEnv(nullptr);
        return len;
    } catch (...) {
        si->loader->setEnv(nullptr);
        return 0;
    }
}

JNIEXPORT jint JNICALL Java_ghidra_app_decompiler_sleigh_SleighNativeLib_oneInstruction
  (JNIEnv *env, jclass cls, jlong sleigh_ptr, jlong addr, jobject cb) {
    SleighInstance* si = (SleighInstance*)sleigh_ptr;
    if (!si) return 0;
    
    si->loader->setEnv(env);
    try {
        Address address(si->sleigh->getDefaultCodeSpace(), (uint64_t)addr);
        JNICallbackPcodeEmit emit(env, cb);
        int len = si->sleigh->oneInstruction(emit, address);
        si->loader->setEnv(nullptr);
        return len;
    } catch (...) {
        si->loader->setEnv(nullptr);
        return 0;
    }
}

}
