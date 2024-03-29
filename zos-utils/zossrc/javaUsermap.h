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
/* Header for class org_zowe_commons_usermap_UserMapper */

#ifndef _Included_org_zowe_commons_usermap_UserMapper
#define _Included_org_zowe_commons_usermap_UserMapper
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     org_zowe_commons_usermap_UserMapper
 * Method:    getUserIDForCertificate
 * Signature: ([B)Lorg/zowe/commons/usermap/CertificateResponse;
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_usermap_UserMapper_getUserIDForCertificate
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     org_zowe_commons_usermap_UserMapper
 * Method:    getUserIDForDN
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Lorg/zowe/commons/usermap/MapperResponse;
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_usermap_UserMapper_getUserIDForDN
  (JNIEnv *, jobject, jstring, jstring);

#ifdef __cplusplus
}
#endif
#endif