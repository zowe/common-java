/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */

#define _OPEN_SYS
#include <unistd.h>
#include <errno.h>
#include "zowe-common-c/h/rusermap.h"
#include "javaUsermap.h"
#include <stdio.h>
/**
 * Define version of JNI for this library
 */
#define JNI_VERSION JNI_VERSION_1_8

#pragma convert(819)
const char *JNI_CLASS_ILLEGAL_ARGUMENT_EXCEPTION = "java/lang/IllegalArgumentException";

const char *JNI_SIGNATURE_METHOD_STRING_INT_INT_INT_INT_VOID = "(Ljava/lang/String;IIII)V";
const char *JNI_SIGNATURE_METHOD_STRING_INT_INT_INT_VOID = "(Ljava/lang/String;III)V";
const char *JNI_METHOD_CONSTRUCTOR = "<init>";

const char *JNI_CLASS_MAPPER_RESPONSE = "org/zowe/commons/usermap/MapperResponse";
const char *JNI_CLASS_CERTIFICATE_RESPONSE = "org/zowe/commons/usermap/CertificateResponse";

const char *JNI_MESSAGE_CANNOT_CONVERT_USER_ID = "Cannot convert userID";
const char *JNI_MESSAGE_DN_NAME_TOO_LONG = "Distinguished name is not allowed to be more than 246 characters";
const char *JNI_MESSAGE_REGISTRY_NAME_TOO_LONG = "Registry name is not allowed to be more than 255 characters";
#pragma convert(0)

jclass certificateClass;
jmethodID certificateClassCtor;
jclass mapperClass;
jmethodID mapperClassCtor;
jclass exception_clazz;

int strnlen(char *txt, int max) {
    if (max < 0) return 0;
    for (int i = 0; i < max; i++) {
        if (!txt[i]) return i;
    }
    return max;
}

/**
 * Return Java environment by virtual machine. It is useful for load and unload event.
 */
JNIEnv* getEnv(JavaVM *vm) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION) != JNI_OK) {
        return NULL;
    }
    return env;
}

 jint JNI_OnLoad(JavaVM *vm, void *reserved) {
     JNIEnv* env = getEnv(vm);
     if (env == NULL) return JNI_ERR;
     certificateClass = (*env) -> NewGlobalRef(env, (*env) -> FindClass(env, JNI_CLASS_CERTIFICATE_RESPONSE));
     certificateClassCtor = (*env) -> GetMethodID(env, certificateClass, JNI_METHOD_CONSTRUCTOR, JNI_SIGNATURE_METHOD_STRING_INT_INT_INT_VOID);
     mapperClass = (*env) -> NewGlobalRef(env, (*env) -> FindClass(env, JNI_CLASS_MAPPER_RESPONSE));

     mapperClassCtor = (*env) -> GetMethodID(env, mapperClass, JNI_METHOD_CONSTRUCTOR, JNI_SIGNATURE_METHOD_STRING_INT_INT_INT_INT_VOID);

     exception_clazz = (*env) -> NewGlobalRef(env, (*env) -> FindClass(env, JNI_CLASS_ILLEGAL_ARGUMENT_EXCEPTION));
     return JNI_VERSION;
 }
/**
 * It reads String from memory in EBCDIC with length up to value in argument length
 */
jstring get_jstring(JNIEnv *env, char* ebcdic, int length)
{
    if (!ebcdic || (length < 0)) return NULL;

    int realSize = strnlen(ebcdic, length);
    if (realSize < length) {
        length = realSize;
    }
    char *output = (char*) __malloc31(length + 1);
    strncpy(output, ebcdic, length);
    output[length] = 0;

    int size = __etoa(output);
    if (size < 0) {
        (*env) -> ThrowNew(env, exception_clazz, JNI_MESSAGE_CANNOT_CONVERT_USER_ID);
        free(output);
        return NULL;
    }

    jstring outputJstring = (*env) -> NewStringUTF(env, output);
    free(output);
    return outputJstring;
}

JNIEXPORT jobject JNICALL Java_org_zowe_commons_usermap_UserMapper_getUserIDForCertificate(JNIEnv *env, jobject obj, jbyteArray certificate) {

    jbyte* cCertificate = (*env) -> GetByteArrayElements(env, certificate, NULL);
    int certificateLength = (*env) -> GetArrayLength(env, certificate);
    char useridRacf[9] = {0};
    int userId_length = 9;
    int returnCodeRacf = 0;
    int reasonCodeRacf = 0;

    int rc = __certificate(__CERTIFICATE_AUTHENTICATE, certificateLength, (char*) cCertificate, userId_length, useridRacf);
    (*env)->ReleaseByteArrayElements(env, certificate, cCertificate, 0);

    e2a(useridRacf, 9);

    jstring jUseridRacf = (*env)->NewStringUTF(env, useridRacf);

    return (*env)->NewObject(env, certificateClass, certificateClassCtor, jUseridRacf, rc, errno, __errno2());
}

JNIEXPORT jobject JNICALL Java_org_zowe_commons_usermap_UserMapper_getUserIDForDN(JNIEnv *env, jobject obj, jstring dn, jstring reg){
    const char* distName = (*env) -> GetStringUTFChars(env, dn, NULL);
    int dnLength = (*env) -> GetStringUTFLength(env, dn);
    if(dnLength > 246) {
            (*env) -> ThrowNew(env, exception_clazz, JNI_MESSAGE_DN_NAME_TOO_LONG);
            return NULL;
    }
    char distinguishedName[246] = {0};
    memcpy(distinguishedName, distName, dnLength);
    (*env) -> ReleaseStringUTFChars(env, dn, distName);
    a2e(&distinguishedName, dnLength);

    const char* registry = (*env)->GetStringUTFChars(env, reg, NULL);
    int registryLength = (*env)->GetStringUTFLength(env, reg);
    if(registryLength > 255) {
            (*env) -> ThrowNew(env, exception_clazz, JNI_MESSAGE_REGISTRY_NAME_TOO_LONG);
            return NULL;
    }
    char registryEbcidic[255] = {0};
    memcpy(registryEbcidic, registry, registryLength);
    (*env) -> ReleaseStringUTFChars(env, reg, registry);
    a2e(&registryEbcidic, registryLength);
    char useridRacf[9] = {0};
    int returnCodeRacf = 0;
    int reasonCodeRacf = 0;

    int rc = getUseridByDN(distinguishedName, dnLength, registryEbcidic, registryLength, useridRacf, &returnCodeRacf, &reasonCodeRacf);

    e2a(useridRacf, 9);

    jstring jUseridRacf = (*env) -> NewStringUTF(env, useridRacf);

    return (*env)->NewObject(env, mapperClass, mapperClassCtor, jUseridRacf, rc, returnCodeRacf, returnCodeRacf, reasonCodeRacf);
}


