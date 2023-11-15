/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */

#include "zowe-common-c/h/rusermap.h"
#include "javaUsermap.h"
#include <stdio.h>


#pragma convert(819)
const char *JNI_CLASS_ILLEGAL_ARGUMENT_EXCEPTION = "java/lang/IllegalArgumentException";

const char *JNI_SIGNATURE_METHOD_STRING_INT_INT_INT_VOID = "(Ljava/lang/String;IIII)V";
const char *JNI_METHOD_CONSTRUCTOR = "<init>";

const char *JNI_CLASS_MAPPER_RESPONSE = "org/zowe/commons/usermap/MapperResponse";

/**
 * error messages in ASCII
 */
const char *JNI_MESSAGE_CANNOT_CONVERT_USER_ID = "Cannot convert userID";
#pragma convert(0)

int strnlen(char *txt, int max) {
    if (max < 0) return 0;
    for (int i = 0; i < max; i++) {
        if (!txt[i]) return i;
    }
    return max;
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
        jclass exception_clazz = (*env) -> FindClass(env, JNI_CLASS_ILLEGAL_ARGUMENT_EXCEPTION);
        (*env) -> ThrowNew(env, exception_clazz, JNI_MESSAGE_CANNOT_CONVERT_USER_ID);
        free(output);
        return NULL;
    }

    jstring outputJstring = (*env) -> NewStringUTF(env, output);
    free(output);
    return outputJstring;
}

JNIEXPORT jobject JNICALL Java_org_zowe_commons_usermap_UserMapper_getUserIDForCertificate(JNIEnv *env, jobject obj, jbyteArray certificate) {


    jbyte* cCertificate = (*env)->GetByteArrayElements(env, certificate, NULL);
    int certificateLength = (*env)->GetArrayLength(env,certificate);
    char useridRacf[9] = {0};
    int returnCodeRacf = 0;
    int reasonCodeRacf = 0;
    printf("\nReturn code %d",returnCodeRacf);
    printf("\nReason code %d",reasonCodeRacf);
    int rc = getUseridByCertificate((char*)cCertificate, certificateLength, useridRacf, &returnCodeRacf, &reasonCodeRacf);
    (*env)->ReleaseByteArrayElements(env, certificate, cCertificate, 0);
    printf("\nReturn code %d",returnCodeRacf);
    printf("\nReason code %d",reasonCodeRacf);
    printf("\nuserid: %s \n",useridRacf);

    if ((*env) -> ExceptionCheck(env)) {
      return NULL;
    }

    e2a(useridRacf,9);

    jclass mapperClass = (*env)->FindClass(env,JNI_CLASS_MAPPER_RESPONSE);

    jmethodID cid = (*env)->GetMethodID(env,mapperClass,JNI_METHOD_CONSTRUCTOR,JNI_SIGNATURE_METHOD_STRING_INT_INT_INT_VOID);

    jstring jUseridRacf = (*env)->NewStringUTF(env,useridRacf);
    return (*env)->NewObject(env,mapperClass,cid,jUseridRacf,rc,returnCodeRacf,returnCodeRacf,reasonCodeRacf);
}

JNIEXPORT jobject JNICALL Java_org_zowe_commons_usermap_UserMapper_getUserIDForDN(JNIEnv *env, jobject obj, jstring dn, jstring reg){
    const char* distName = (*env)->GetStringUTFChars(env,dn,NULL);
    int dnLength = (*env)->GetStringUTFLength(env,dn);
    char distinguishedName[246] = {0};
    memcpy(distinguishedName,distName,dnLength);
    a2e(&distinguishedName,dnLength);

    const char* registry = (*env)->GetStringUTFChars(env,reg,NULL);
    int registryLength = (*env)->GetStringUTFLength(env,reg);
    char registryEbcidic[255] = {0};
    memcpy(registryEbcidic,registry,registryLength);
    a2e(&registryEbcidic,registryLength);
    char useridRacf[9] = {0};
    int returnCodeRacf = 0;
    int reasonCodeRacf = 0;
    printf("\nEBCIDIC dn: %s",distinguishedName);
    printf("\nEBCIDIC registry: %s",registryEbcidic);
    printf("\nReturn code DN %d",returnCodeRacf);
    printf("\nReason code DN %d",reasonCodeRacf);
    int rc = getUseridByDN(distinguishedName,dnLength,registryEbcidic,registryLength,useridRacf,&returnCodeRacf,&reasonCodeRacf);
    printf("\nReturn code DN %d",returnCodeRacf);
    printf("\nReason code DN %d",reasonCodeRacf);
    printf("\nuserid for DN: %s \n",useridRacf);
    e2a(useridRacf,9);

    jclass mapperClass = (*env)->FindClass(env,JNI_CLASS_MAPPER_RESPONSE);

    jmethodID cid = (*env)->GetMethodID(env,mapperClass,JNI_METHOD_CONSTRUCTOR,JNI_SIGNATURE_METHOD_STRING_INT_INT_INT_VOID);

    jstring jUseridRacf = (*env)->NewStringUTF(env,useridRacf);

    return (*env)->NewObject(env,mapperClass,cid,jUseridRacf,rc,returnCodeRacf,returnCodeRacf,reasonCodeRacf);
}


