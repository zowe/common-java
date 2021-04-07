/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */

/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_zowe_commons_attls_AttlsContext */

#ifndef _Included_org_zowe_commons_attls_AttlsContext
#define _Included_org_zowe_commons_attls_AttlsContext
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    clean
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_clean
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    getStatPolicy
 * Signature: ()Lorg/zowe/commons/attls/StatPolicy;
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getStatPolicy
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    getStatConn
 * Signature: ()Lorg/zowe/commons/attls/StatConn;
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getStatConn
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    getProtocol
 * Signature: ()Lorg/zowe/commons/attls/Protocol;
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getProtocol
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    getNegotiatedCipher2
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_zowe_commons_attls_AttlsContext_getNegotiatedCipher2
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    getSecurityType
 * Signature: ()Lorg/zowe/commons/attls/SecurityType;
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getSecurityType
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    getUserId
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_zowe_commons_attls_AttlsContext_getUserId
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    getFips140
 * Signature: ()Lorg/zowe/commons/attls/Fips140;
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getFips140
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    getFlags
 * Signature: ()B
 */
JNIEXPORT jbyte JNICALL Java_org_zowe_commons_attls_AttlsContext_getFlags
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    getNegotiatedCipher4
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_zowe_commons_attls_AttlsContext_getNegotiatedCipher4
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    getNegotiatedKeyShare
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_zowe_commons_attls_AttlsContext_getNegotiatedKeyShare
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    getCrtificate
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_zowe_commons_attls_AttlsContext_getCertificate
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    initConnection
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_initConnection
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    resetSession
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_resetSession
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    resetCipher
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_resetCipher
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    stopConnection
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_stopConnection
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    allowHandShakeTimeout
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_allowHandShakeTimeout
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    resetWriteCipher
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_resetWriteCipher
  (JNIEnv *, jobject);

/*
 * Class:     org_zowe_commons_attls_AttlsContext
 * Method:    sendSessionTicket
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_sendSessionTicket
  (JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif
#endif
