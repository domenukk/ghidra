#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "demangle.h"

extern "C" {

/*
 * Class:     ghidra_app_util_demangler_gnu_GnuDemanglerNative
 * Method:    demangleJni
 * Signature: (Ljava/lang/String;I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_ghidra_app_util_demangler_gnu_GnuDemanglerNative_demangleJni
  (JNIEnv *env, jclass cls, jstring mangled, jint options) {
    


    if (mangled == NULL) {
        return NULL;
    }
    
    const char *mangled_cstr = env->GetStringUTFChars(mangled, NULL);
    if (mangled_cstr == NULL) {
        return NULL; // OutOfMemoryError already thrown
    }

    char *demangled = cplus_demangle(mangled_cstr, options);
    
    env->ReleaseStringUTFChars(mangled, mangled_cstr);

    if (demangled == NULL) {
        return NULL;
    }

    jstring result = env->NewStringUTF(demangled);
    free(demangled);

    return result;
}

}
