
#include <jni.h>
#include <string>
using namespace std;

#include "RSAUtils.h"
#include "openssl/crypto.h"
template<typename T, int N>
char (&ArraySizeHelper(T (&array)[N]))[N];
// reference from https://fucknmb.com/2017/04/09/Android%E5%9C%A8NDK%E5%B1%82%E4%BD%BF%E7%94%A8OpenSSL%E8%BF%9B%E8%A1%8CRSA%E5%8A%A0%E5%AF%86/
#define NELEMS(x) (sizeof(ArraySizeHelper(x)))

#ifndef CLASSNAME
#define CLASSNAME "com/test/rsa/MainActivity"
#endif

extern "C" JNIEXPORT jstring JNICALL
Java_com_test_rsa_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {

    return nullptr;
}
//
jstring native_rsa(JNIEnv *env, jobject thiz, jstring base64PublicKey, jstring content) {
    //jstring 转 char*
    char *base64PublicKeyChars = (char *) env->GetStringUTFChars(base64PublicKey, NULL);
    //char* 转 string
    string base64PublicKeyString = string(base64PublicKeyChars);
    //生成公钥字符串
    string generatedPublicKey = generatePublicKey(base64PublicKeyString);
    //释放
    env->ReleaseStringUTFChars(base64PublicKey, base64PublicKeyChars);
    //jstring 转 char*
    char *contentChars = (char *) env->GetStringUTFChars(content, NULL);
    //char* 转 string
    string contentString = string(contentChars);
    //释放
    env->ReleaseStringUTFChars(content, contentChars);

    //调用RSA加密函数加密
    string rsaResult = encryptRSA(generatedPublicKey, contentString);
    if (rsaResult.empty()) {
        return NULL;
    }
    //将密文进行base64
    string base64RSA = base64_encode(rsaResult);
    if (base64RSA.empty()) {
        return NULL;
    }
    //string -> char* -> jstring 返回
    jstring result = env->NewStringUTF(base64RSA.c_str());

    return result;
}
static const JNINativeMethod sMethods[] = {
        {
                const_cast<char *>("native_rsa"),
                const_cast<char *>("(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
                reinterpret_cast<void *>(native_rsa)
        }
};

int registerNativeMethods(JNIEnv *env, const char *className, const JNINativeMethod *methods,
                          const int numMethods) {
    jclass clazz = env->FindClass(className);
    if (!clazz) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, methods, numMethods) != 0) {
        env->DeleteLocalRef(clazz);
        return JNI_FALSE;
    }
    env->DeleteLocalRef(clazz);
    return JNI_TRUE;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }
    registerNativeMethods(env, CLASSNAME, sMethods, NELEMS(sMethods));
    return JNI_VERSION_1_6;
}
