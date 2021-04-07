/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */

#include "AttlsContext.h"
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include <resolv.h>
#include <ezbztlsc.h>

/**
 * The fields between the pragmas below need to be in ASCII.
 *
 * Runtime translations can be done via:
 *   __etoa() EBCDIC to ASCII
 *   __atoe() ASCII to EBCDIC
 */
#if defined(__IBMC__) || defined(__IBMCPP__)
#pragma convert(819)
#endif

/**
 * type signature of properties used in AttlsContext in ASCII
 */
const char *JNI_SIGNATURE_PROPERTY_BOOLEAN = "Z";
const char *JNI_SIGNATURE_PROPERTY_INTEGER = "I";
const char *JNI_SIGNATURE_PROPERTY_BYTE_ARRAY = "[B";
const char *JNI_SIGNATURE_PROPERTY_STRING = "Ljava/lang/String;";
const char *JNI_SIGNATURE_PROPERTY_STAT_POLICY = "Lorg/zowe/commons/attls/StatPolicy;";
const char *JNI_SIGNATURE_PROPERTY_STAT_CONN = "Lorg/zowe/commons/attls/StatConn;";
const char *JNI_SIGNATURE_PROPERTY_PROTOCOL = "Lorg/zowe/commons/attls/Protocol;";
const char *JNI_SIGNATURE_PROPERTY_SECURITY_TYPE = "Lorg/zowe/commons/attls/SecurityType;";
const char *JNI_SIGNATURE_PROPERTY_FIPS_140 = "Lorg/zowe/commons/attls/Fips140;";

/**
 * type signature of methods used in AttlsContext in ASCII
 */
const char *JNI_SIGNATURE_METHOD_BYTE_BYTE_PROTOCOL = "(BB)Lorg/zowe/commons/attls/Protocol;";
const char *JNI_SIGNATURE_METHOD_NONE_BYTE = "()B";
const char *JNI_SIGNATURE_METHOD_ENUM_BYTE_VOID = "(Ljava/lang/Enum;B)V";
const char *JNI_SIGNATURE_METHOD_ENUM_BYTE_BYTE_VOID = "(Ljava/lang/Enum;BB)V";
const char *JNI_SIGNATURE_METHOD_INT_INT_INT_VOID = "(III)V";
const char *JNI_SIGNATURE_METHOD_NONE_ARRAY_PREFIX = "()[L";
const char *JNI_SIGNATURE_METHOD_SEMICOLON_SUFFIX = ";";

/**
 * name of properties used in AttlsContext in ASCII
 */
const char *JNI_PROPERTY_BUFFER_CERTIFICATE_LENGTH = "BUFFER_CERTIFICATE_LENGTH";
const char *JNI_PROPERTY_ALWAYS_LOAD_CERTIFICATE = "alwaysLoadCertificate";
const char *JNI_PROPERTY_ID = "id";
const char *JNI_PROPERTY_IOCTL = "ioctl";
const char *JNI_PROPERTY_BUFFER_CERTIFICATE = "bufferCertificate";
const char *JNI_PROPERTY_QUERY_LOADED = "queryLoaded";
const char *JNI_PROPERTY_CERTIFICATE_LOADED = "certificateLoaded";
const char *JNI_PROPERTY_STAT_POLICY_CACHE = "statPolicyCache";
const char *JNI_PROPERTY_STAT_CONN_CACHE = "statConnCache";
const char *JNI_PROPERTY_PROTOCOL_CACHE = "protocolCache";
const char *JNI_PROPERTY_NEGOTIATED_CIPHER_2_CACHE = "negotiatedCipher2Cache";
const char *JNI_PROPERTY_SECURITY_TYPE_CACHE = "securityTypeCache";
const char *JNI_PROPERTY_USER_ID_CACHE = "userIdCache";
const char *JNI_PROPERTY_FIPS_140_CACHE = "fips140Cache";
const char *JNI_PROPERTY_NEGOTIATED_CIPHER_4_CACHE = "negotiatedCipher4Cache";
const char *JNI_PROPERTY_NEGOTIATED_KEY_SHARE_CACHE = "negotiatedKeyShareCache";
const char *JNI_PROPERTY_CERTIFICATE_CACHE = "certificateCache";

/**
 * name of classes used in AttlsContext in ASCII
 */
const char *JNI_CLASS_ATTLS_CONTEXT = "org/zowe/commons/attls/AttlsContext";
const char *JNI_CLASS_STAT_POLICY = "org/zowe/commons/attls/StatPolicy";
const char *JNI_CLASS_STAT_CONN = "org/zowe/commons/attls/StatConn";
const char *JNI_CLASS_SECURITY_TYPE = "org/zowe/commons/attls/SecurityType";
const char *JNI_CLASS_FIPS_140 = "org/zowe/commons/attls/Fips140";
const char *JNI_CLASS_PROTOCOL = "org/zowe/commons/attls/Protocol";
const char *JNI_CLASS_ILLEGAL_ARGUMENT_EXCEPTION = "java/lang/IllegalArgumentException";
const char *JNI_CLASS_UNKNOWN_ENUM_VALUE_EXCEPTION = "org/zowe/commons/attls/UnknownEnumValueException";
const char *JNI_CLASS_IOCTL_CALL_EXCEPTION = "org/zowe/commons/attls/IoctlCallException";

/**
 * name of method used in AttlsContext in ASCII
 */
const char *JNI_METHOD_CONSTRUCTOR = "<init>";
const char *JNI_METHOD_VALUE_OF = "valueOf";
const char *JNI_METHOD_VALUES = "values";
const char *JNI_METHOD_GET_VALUE = "getValue";

/**
 * error messages in ASCII
 */
const char *JNI_MESSAGE_CANNOT_CONVERT_USER_ID = "Cannot convert userID";

#if defined(__IBMC__) || defined(__IBMCPP__)
#pragma convert(0)
#endif

/**
 * JAVA constants
 */
#define JNI_FALSE  0
#define JNI_TRUE   1

/**
 * Define version of JNI for this library
 */
#define JNI_VERSION JNI_VERSION_1_8

/**
  * Struct for fast mapping byte values into enumeration. It is possible to use to value which are close to zero.
  * It prepare array and mapping is via index of arrray.
  */
typedef struct enum_map {
    // enumeration Class
    jclass clazz;
    // enumeration class name with slashes
    const char* clazzName;
    // array with all values from enumeration
    jobject* values;
    // max value stored into array (to check input value)
    int max_value;
} EnumMap;

/**
 * AttlsContext.class to easy using this constant
 */
jclass attls_context_clazz;

/**
 * Cached references to properties of AttlsContext to faster using
 */
jfieldID always_load_certificate_field;
jfieldID id_field;
jfieldID ioctl_field;
jfieldID buffer_certificate_field;
jfieldID query_loaded_field;
jfieldID certificate_loaded_field;
jfieldID stat_policy_cache_field;
jfieldID stat_conn_cache_field;
jfieldID protocol_cache_field;
jfieldID negotiated_cipher2_cache_field;
jfieldID security_type_cache_field;
jfieldID user_id_cache_field;
jfieldID fips140_cache_field;
jfieldID negotiated_cipher4_cache_field;
jfieldID negotiated_key_share_cache_field;
jfieldID certificate_cache_field;

/**
 * Size of buffer to fetch certificate
 */
int buffer_certificate_size;

/**
 * Prepared mapping from byte value into enumerations
 */
EnumMap* stat_policy_enum_map;
EnumMap* stat_conn_enum_map;
EnumMap* security_type_enum_map;
EnumMap* fips140_enum_map;

/**
 * Class and filed of protocol enumeration (there is not possible to use EnumMap, because it is identified by 2 bytes)
 */
jclass enum_protocol_clazz;
jmethodID protocol_value_of_method_ID;

/**
 * It reads String from memory in EBCDIC with length up to value in argument length
 */
jstring get_jstring(JNIEnv *env, char* ebcdic, int length)
{
    char *output = (char*) __malloc31(length + 1);
    strcpy(output, ebcdic, length);

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

/**
 * It prepares EnumMap from enum class to fast mapping.
 */
EnumMap* load_enum_map(JNIEnv *env, const char* clazz)
{
    // construct signature of static method <Enum>.values()
    char* signature = (char*) __malloc31(
        strlen(clazz) +
        strlen(JNI_SIGNATURE_METHOD_NONE_ARRAY_PREFIX) +
        strlen(JNI_SIGNATURE_METHOD_SEMICOLON_SUFFIX) +
        1
    );
    strcpy(signature, JNI_SIGNATURE_METHOD_NONE_ARRAY_PREFIX);
    strcat(signature, clazz);
    strcat(signature, JNI_SIGNATURE_METHOD_SEMICOLON_SUFFIX);

    // call static method <Enum>.values()
    jclass enum_clazz = (*env) -> FindClass(env, clazz);
    jmethodID method_values = (*env) -> GetStaticMethodID(env, enum_clazz, JNI_METHOD_VALUES, signature);
    jobjectArray values = (*env) -> CallStaticObjectMethod(env, enum_clazz, method_values);

    // find method byte <Enum>.getValue()
    jmethodID method_get_value = (*env) -> GetMethodID(env, enum_clazz, JNI_METHOD_GET_VALUE, JNI_SIGNATURE_METHOD_NONE_BYTE);

    // find the highest value
    jbyte max_value = 0;
    int count = (*env) -> GetArrayLength(env, values);
    for (int i = 0; i < count; i++) {
        jclass item = (*env) -> GetObjectArrayElement(env, values, i);
        jbyte value = (*env) -> CallByteMethod(env, item, method_get_value);
        if (value > max_value) max_value = value;
    }

    // construct struct EnumMap with empty values
    EnumMap* out = (EnumMap*) __malloc31(sizeof(EnumMap));
    out -> max_value = (int) max_value;
    out -> clazz = (*env) -> NewGlobalRef(env, enum_clazz);
    out -> clazzName = clazz;
    int array_size = (max_value + 1) * sizeof(jobject*);
    out -> values = (jobject*) __malloc31(array_size);
    memset(out -> values, 0, array_size);

    // fill values in the array
    for (int i = 0; i < count; i++) {
        jobject item = (*env) -> GetObjectArrayElement(env, values, i);
        jbyte value = (*env) -> CallByteMethod(env, item, method_get_value);
        out -> values[value] = (*env) -> NewGlobalRef(env, item);
    }

    return out;
}

/**
 * Throws UnknownEnumValueException with set values
 */
void throw_unknown_enum_value(JNIEnv *env, EnumMap* enum_map, unsigned char value) {
    jclass exception_clazz = (*env) -> FindClass(env, JNI_CLASS_UNKNOWN_ENUM_VALUE_EXCEPTION);
    jmethodID constructor = (*env) -> GetMethodID(env, exception_clazz, JNI_METHOD_CONSTRUCTOR, JNI_SIGNATURE_METHOD_ENUM_BYTE_VOID);
    jobject exception = (*env) -> NewObject(env, exception_clazz, constructor, enum_map -> clazz, (jbyte) value);
    (*env) -> Throw(env, exception);
}

/**
 * Returns enum value from EnumMap by byte value
 */
jobject get_enum(JNIEnv* env, EnumMap* enum_map, unsigned char value) {
    // check if value is not greather than maximal known, otherwise throw exception
    if (enum_map -> max_value < value) {
        throw_unknown_enum_value(env, enum_map, value);
        return NULL;
    }

    // find the enum, if value is null, it is not known at the moment and throw exception
    jobject out = enum_map -> values[value];
    if (!out) {
        throw_unknown_enum_value(env, enum_map, value);
    }
    return out;
}

/**
 * Return Java environment by virtual machine. It is useful for load and unload event.
 */
JNIEnv* getEnv(JavaVM *vm)
{
    JNIEnv* env;
    (*vm) -> GetEnv(vm, &env, JNI_VERSION);
    return env;
}

/**
 * Initialization of native library.
 * I fetches all constant from virtual machine to be used in another methods. It fetches fields of AttlsContext,
 * using classes and their methods. It also prepare EnumMap for all possible enumerations.
 */
jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv* env = getEnv(vm);

    // fetch AtllsContext.class
    jclass clazz = (*env) -> FindClass(env, JNI_CLASS_ATTLS_CONTEXT);
    attls_context_clazz = (*env) -> NewGlobalRef(env, clazz);

    // fetch size of certificate length
    jfieldID buffer_certificate_size_field = (*env) -> GetStaticFieldID(env, clazz, JNI_PROPERTY_BUFFER_CERTIFICATE_LENGTH, JNI_SIGNATURE_PROPERTY_INTEGER);
    buffer_certificate_size = (*env) -> GetStaticIntField(env, clazz, buffer_certificate_size_field);

    // fetch all fields to properties of AttlsContext
    always_load_certificate_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_ALWAYS_LOAD_CERTIFICATE, JNI_SIGNATURE_PROPERTY_BOOLEAN);
    id_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_ID, JNI_SIGNATURE_PROPERTY_INTEGER);
    ioctl_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_IOCTL, JNI_SIGNATURE_PROPERTY_BYTE_ARRAY);
    buffer_certificate_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_BUFFER_CERTIFICATE, JNI_SIGNATURE_PROPERTY_BYTE_ARRAY);
    query_loaded_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_QUERY_LOADED, JNI_SIGNATURE_PROPERTY_BOOLEAN);
    certificate_loaded_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_CERTIFICATE_LOADED, JNI_SIGNATURE_PROPERTY_BOOLEAN);
    stat_policy_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_STAT_POLICY_CACHE, JNI_SIGNATURE_PROPERTY_STAT_POLICY);
    stat_conn_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_STAT_CONN_CACHE, JNI_SIGNATURE_PROPERTY_STAT_CONN);
    protocol_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_PROTOCOL_CACHE, JNI_SIGNATURE_PROPERTY_PROTOCOL);
    negotiated_cipher2_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_NEGOTIATED_CIPHER_2_CACHE, JNI_SIGNATURE_PROPERTY_STRING);
    security_type_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_SECURITY_TYPE_CACHE, JNI_SIGNATURE_PROPERTY_SECURITY_TYPE);
    user_id_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_USER_ID_CACHE, JNI_SIGNATURE_PROPERTY_STRING);
    fips140_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_FIPS_140_CACHE, JNI_SIGNATURE_PROPERTY_FIPS_140);
    negotiated_cipher4_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_NEGOTIATED_CIPHER_4_CACHE, JNI_SIGNATURE_PROPERTY_STRING);
    negotiated_key_share_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_NEGOTIATED_KEY_SHARE_CACHE, JNI_SIGNATURE_PROPERTY_STRING);
    certificate_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_CERTIFICATE_CACHE, JNI_SIGNATURE_PROPERTY_BYTE_ARRAY);

    // prepare EnumMap for all possible relevant enumerations
    stat_policy_enum_map = load_enum_map(env, JNI_CLASS_STAT_POLICY);
    stat_conn_enum_map = load_enum_map(env, JNI_CLASS_STAT_CONN);
    security_type_enum_map = load_enum_map(env, JNI_CLASS_SECURITY_TYPE);
    fips140_enum_map = load_enum_map(env, JNI_CLASS_FIPS_140);

    // fetch Protocol.class and method Protocol.values() - cannot use EnumMap (it has 2 bytes to identify)
    enum_protocol_clazz = (*env) -> NewGlobalRef(env, (*env) -> FindClass(env, JNI_CLASS_PROTOCOL));
    protocol_value_of_method_ID = (*env) -> GetStaticMethodID(env, enum_protocol_clazz, JNI_METHOD_VALUE_OF, JNI_SIGNATURE_METHOD_BYTE_BYTE_PROTOCOL);

    return JNI_VERSION;
}

/**
 * Returns true if query was done and data are prepared in memory, otherwise false (before first call or after clean).
 */
jboolean isQueryLoaded(JNIEnv *env, jobject obj)
{
    return (*env) -> GetBooleanField(env, obj, query_loaded_field);
}

/**
 * Returns true if certificate was fetched, otherwise false (before first call or after clean).
 */
 jboolean isCertificateLoaded(JNIEnv *env, jobject obj)
{
    return (*env) -> GetBooleanField(env, obj, certificate_loaded_field);
}

/**
 * Creates and returns array to store request and answer of ioctl, it is stored in AttlsContext.ioctl
 */
jbyteArray createIoctl(JNIEnv *env, jobject obj)
{
    jbyteArray array = (*env) -> NewByteArray(env, sizeof(struct TTLS_IOCTL));
    (*env) -> SetObjectField(env, obj, ioctl_field, array);
    return array;
}

/**
 * Returns request for ioctl, if it has not created, create new one.
 */
struct TTLS_IOCTL getIoctl(JNIEnv *env, jobject obj)
{
    jbyteArray array = (*env) -> GetObjectField(env, obj, ioctl_field);
    if (!array) array = createIoctl(env, obj);
    struct TTLS_IOCTL* output = (struct TTLS_IOCTL*) (*env) -> GetByteArrayElements(env, array, 0);
    return *output;
}

/**
 * Creates and returns array to store certificate by ioctl, it is stored in AttlsContext.bufferCertificate
 */
jbyteArray createCertificateBuffer(JNIEnv *env, jobject obj)
{
    jbyteArray array = (*env) -> NewByteArray(env, buffer_certificate_size);
    (*env) -> SetObjectField(env, obj, buffer_certificate_field, array);
    return array;
}

/**
 * Returns array for storing a certificate, if it has not created, create new one.
 */
jbyte* getCertificateBuffer(JNIEnv *env, jobject obj)
{
    jbyteArray array = (*env) -> GetObjectField(env, obj, buffer_certificate_field);
    if (!array) array = createCertificateBuffer(env, obj);
    return (*env) -> GetByteArrayElements(env, array, 0);
}

/**
 * It return file descriptor of socket. It is stored in AttlsContext.id.
 */
int getSocket(JNIEnv *env, jobject obj) {
    return (*env) -> GetIntField(env, obj, id_field);
}

/**
 * It call ioctl to fetch query or certificate. Type of call is determinated by arguments query and certificate.
 * Also in the case alwaysLoadCertificate is set to true certificated is fetched.
 */
struct TTLS_IOCTL load(JNIEnv *env, jobject obj, jboolean query, jboolean certificate)
{
    // get struct of request
    struct TTLS_IOCTL ioc = getIoctl(env, obj);

    // construct request

    ioc.TTLSi_Ver = TTLS_VERSION1;

    if (!certificate) {
        certificate |= (*env) -> GetStaticBooleanField(env, attls_context_clazz, always_load_certificate_field);
    }
    ioc.TTLSi_Req_Type = 0;
    if (query) ioc.TTLSi_Req_Type |= TTLS_QUERY_ONLY;
    if (certificate) ioc.TTLSi_Req_Type |= TTLS_RETURN_CERTIFICATE;

    ioc.TTLSi_BufferPtr = certificate ? (char*) getCertificateBuffer(env, obj) : (char*) NULL;
    ioc.TTLSi_BufferLen = certificate ? buffer_certificate_size : 0;

    // call ioctl
    int rcIoctl = ioctl(getSocket(env, obj), SIOCTTLSCTL, (char*) &ioc);

    // if ioctl returns an error throw exception
    if (rcIoctl < 0) {
        jclass exception_clazz = (*env) -> FindClass(env, JNI_CLASS_IOCTL_CALL_EXCEPTION);
        jmethodID constructor = (*env) -> GetMethodID(env, exception_clazz, JNI_METHOD_CONSTRUCTOR, JNI_SIGNATURE_METHOD_INT_INT_INT_VOID);
        jobject exception = (*env) -> NewObject(env, exception_clazz, constructor,
            (jint) rcIoctl, (jint) errno, (jint) __errno2());
        (*env) -> Throw(env, exception);
    }

    return ioc;
}

/**
 * Return ioctl with data from query call. If data are available in memory, returns them, otherwise call ioctl.
 * If alwaysLoadCertificate is set to true certificated is also fetched.
 */
struct TTLS_IOCTL requireQuery(JNIEnv *env, jobject obj)
{
    if (isQueryLoaded(env, obj)) return getIoctl(env,obj);
    return load(env, obj, JNI_TRUE, JNI_FALSE);
}

/**
 * Return ioctl with data with certificate. If data are available in memory, returns them, otherwise call ioctl.
 */
struct TTLS_IOCTL requireCertificate(JNIEnv *env, jobject obj)
{
    if (isCertificateLoaded(env, obj)) return getIoctl(env,obj);
    return load(env, obj, JNI_FALSE, JNI_TRUE);
}

/**
 * Clean state of AttlsContext. It remove all cached data. Next call will fetch new one.
 */
JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_clean(JNIEnv *env, jobject obj)
{
    // clean flags about loaded data
    (*env) -> SetBooleanField(env, obj, query_loaded_field, JNI_FALSE);
    (*env) -> SetBooleanField(env, obj, certificate_loaded_field, JNI_FALSE);

    // clean all cached values (Java objects)
    (*env) -> SetObjectField(env, obj, stat_policy_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, stat_conn_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, protocol_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, negotiated_cipher2_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, security_type_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, user_id_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, fips140_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, negotiated_cipher4_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, negotiated_key_share_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, certificate_cache_field, NULL);
}

/**
 * Return or load and cache value AttlsContext.statPolicyCache
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getStatPolicy(JNIEnv *env, jobject obj)
{
    jobject out = (*env) -> GetObjectField(env, obj, stat_policy_cache_field);
    if (out) return out;

    struct TTLS_IOCTL ioctl = requireQuery(env, obj);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    out = get_enum(env, stat_policy_enum_map, ioctl.TTLSi_Stat_Policy);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    (*env) -> SetObjectField(env, obj, stat_policy_cache_field, out);
    return out;
}

/**
 * Return or load and cache value AttlsContext.statConnCache
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getStatConn(JNIEnv *env, jobject obj)
{
    jobject out = (*env) -> GetObjectField(env, obj, stat_conn_cache_field);
    if (out) return out;

    struct TTLS_IOCTL ioctl = requireQuery(env, obj);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    out = get_enum(env, stat_conn_enum_map, ioctl.TTLSi_Stat_Conn);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    (*env) -> SetObjectField(env, obj, stat_conn_cache_field, out);
    return out;
}

/**
 * Return or load and cache value AttlsContext.protocolCache
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getProtocol(JNIEnv *env, jobject obj)
{
    jobject out = (*env) -> GetObjectField(env, obj, protocol_cache_field);
    if (out) return out;

    struct TTLS_IOCTL ioctl = requireQuery(env, obj);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    // call static method Protocol.valueOf(byte, byte)
    out = (*env) -> CallStaticObjectMethod(env, enum_protocol_clazz, protocol_value_of_method_ID,
        (jbyte) ioctl.TTLSi_SSL_Protocol.Prot_bytes.Prot_Ver,
        (jbyte) ioctl.TTLSi_SSL_Protocol.Prot_bytes.Prot_Mod);
    if (!out)
    {
        // if enum was not fetched, throw exception
        jclass exception_clazz = (*env) -> FindClass(env, JNI_CLASS_UNKNOWN_ENUM_VALUE_EXCEPTION);
        jmethodID constructor = (*env) -> GetMethodID(env, exception_clazz, JNI_METHOD_CONSTRUCTOR, JNI_SIGNATURE_METHOD_ENUM_BYTE_BYTE_VOID);
        jobject exception = (*env) -> NewObject(env, exception_clazz, constructor, enum_protocol_clazz,
            (jbyte) ioctl.TTLSi_SSL_Protocol.Prot_bytes.Prot_Ver,
            (jbyte) ioctl.TTLSi_SSL_Protocol.Prot_bytes.Prot_Mod);
        (*env) -> Throw(env, exception);
        return NULL;
    }

    (*env) -> SetObjectField(env, obj, protocol_cache_field, out);
    return out;
}

/**
 * Return or load and cache value AttlsContext.negotiatedCipher2Cache
 */
JNIEXPORT jstring JNICALL Java_org_zowe_commons_attls_AttlsContext_getNegotiatedCipher2(JNIEnv *env, jobject obj)
{
    jstring out = (*env) -> GetObjectField(env, obj, negotiated_cipher2_cache_field);
    if (out) return out;

    struct TTLS_IOCTL ioctl = requireQuery(env, obj);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    out = get_jstring(env, ioctl.TTLSi_Neg_Cipher, 2);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    (*env) -> SetObjectField(env, obj, negotiated_cipher2_cache_field, out);
    return out;
}

/**
 * Return or load and cache value AttlsContext.securityTypeCache
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getSecurityType(JNIEnv *env, jobject obj)
{
    jobject out = (*env) -> GetObjectField(env, obj, security_type_cache_field);
    if (out) return out;

    struct TTLS_IOCTL ioctl = requireQuery(env, obj);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    out = get_enum(env, security_type_enum_map, ioctl.TTLSi_Sec_Type);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    (*env) -> SetObjectField(env, obj, security_type_cache_field, out);
    return out;
}

/**
 * Return or load and cache value AttlsContext.statPolicyCache
 */
JNIEXPORT jstring JNICALL Java_org_zowe_commons_attls_AttlsContext_getUserId(JNIEnv *env, jobject obj)
{
    jstring out = (*env) -> GetObjectField(env, obj, user_id_cache_field);
    if (out) return out;

    struct TTLS_IOCTL ioctl = requireQuery(env, obj);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    out = get_jstring(env, ioctl.TTLSi_UserID, ioctl.TTLSi_UserID_Len);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    (*env) -> SetObjectField(env, obj, user_id_cache_field, out);
    return out;
}

/**
 * Return or load and cache value AttlsContext.fips140Cache
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getFips140(JNIEnv *env, jobject obj)
{
    jobject out = (*env) -> GetObjectField(env, obj, fips140_cache_field);
    if (out) return out;

    struct TTLS_IOCTL ioctl = requireQuery(env, obj);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    out = get_enum(env, fips140_enum_map, ioctl.TTLSi_FIPS140);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    (*env) -> SetObjectField(env, obj, fips140_cache_field, out);
    return out;
}

/**
 * Return or load value flag
 */
JNIEXPORT jbyte JNICALL Java_org_zowe_commons_attls_AttlsContext_getFlags(JNIEnv *env, jobject obj)
{
    struct TTLS_IOCTL ioctl = requireQuery(env, obj);
    if ((*env) -> ExceptionCheck(env)) return 0;

    return (jbyte) ioctl.TTLSi_Flags;
}

/**
 * Return or load and cache value AttlsContext.negotiatedCipher4Cache
 */
JNIEXPORT jstring JNICALL Java_org_zowe_commons_attls_AttlsContext_getNegotiatedCipher4(JNIEnv *env, jobject obj)
{
    jstring out = (*env) -> GetObjectField(env, obj, negotiated_cipher4_cache_field);
    if (out) return out;

    struct TTLS_IOCTL ioctl = requireQuery(env, obj);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    out = get_jstring(env, ioctl.TTLSi_Neg_Cipher4, 4);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    (*env) -> SetObjectField(env, obj, negotiated_cipher4_cache_field, out);
    return out;
}

/**
 * Return or load and cache value AttlsContext.negotiatedKeyShareCache
 */
JNIEXPORT jstring JNICALL Java_org_zowe_commons_attls_AttlsContext_getNegotiatedKeyShare(JNIEnv *env, jobject obj)
{
    jstring out = (*env) -> GetObjectField(env, obj, negotiated_key_share_cache_field);
    if (out) return out;

    struct TTLS_IOCTL ioctl = requireQuery(env, obj);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    out = get_jstring(env, ioctl.TTLSi_Neg_KeyShare, 4);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    (*env) -> SetObjectField(env, obj, negotiated_key_share_cache_field, out);
    return out;
}

/**
 * Return or load and cache value AttlsContext.certificateCache
 */
JNIEXPORT jbyteArray JNICALL Java_org_zowe_commons_attls_AttlsContext_getCertificate(JNIEnv *env, jobject obj)
{
    jbyteArray out = (*env) -> GetObjectField(env, obj, certificate_cache_field);
    if (out) return out;

    struct TTLS_IOCTL ioctl = requireCertificate(env, obj);
    if ((*env) -> ExceptionCheck(env)) return NULL;

    out = (*env) -> NewByteArray(env, ioctl.TTLSi_Cert_Len);
    (*env) -> SetByteArrayRegion(env, out, 0, ioctl.TTLSi_Cert_Len, ioctl.TTLSi_BufferPtr);

    (*env) -> SetObjectField(env, obj, certificate_cache_field, out);
    return out;
}

/**
 * This method call ioctl with request type by argument command. It is using to call other request type than query and
 * protocol (They are called via method load).
 */
void issueCommand(JNIEnv *env, jobject obj, int command)
{
    struct TTLS_IOCTL ioc = getIoctl(env, obj);

    ioc.TTLSi_Ver = TTLS_VERSION1;
    ioc.TTLSi_Req_Type = command;
    ioc.TTLSi_BufferPtr = NULL;
    ioc.TTLSi_BufferLen = 0;

    int rcIoctl = ioctl(getSocket(env, obj), SIOCTTLSCTL, (char *)&ioc);

    if (rcIoctl < 0) {
        jclass exception_clazz = (*env) -> FindClass(env, JNI_CLASS_IOCTL_CALL_EXCEPTION);
        jmethodID constructor = (*env) -> GetMethodID(env, exception_clazz, JNI_METHOD_CONSTRUCTOR, JNI_SIGNATURE_METHOD_INT_INT_INT_VOID);
        jobject exception = (*env) -> NewObject(env, exception_clazz, constructor,
            (jint) rcIoctl, (jint) errno, (jint) __errno2());
        (*env) -> Throw(env, exception);
        return;
    }
}

JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_initConnection(JNIEnv *env, jobject obj)
{
    issueCommand(env, obj, TTLS_INIT_CONNECTION);
}

JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_resetSession(JNIEnv *env, jobject obj)
{
    issueCommand(env, obj, TTLS_RESET_SESSION);
}

JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_resetCipher(JNIEnv *env, jobject obj)
{
    issueCommand(env, obj, TTLS_RESET_CIPHER);
}

JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_stopConnection(JNIEnv *env, jobject obj)
{
    issueCommand(env, obj, TTLS_STOP_CONNECTION);
}

JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_allowHandShakeTimeout(JNIEnv *env, jobject obj)
{
    issueCommand(env, obj, TTLS_ALLOW_HSTIMEOUT);
}

JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_resetWriteCipher(JNIEnv *env, jobject obj)
{
    issueCommand(env, obj, TTLS_RESET_WRITE_CIPHER);
}

JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_sendSessionTicket(JNIEnv *env, jobject obj)
{
    issueCommand(env, obj, TTLS_SEND_SESSION_TICKET);
}

/**
 * Free memory using for EnumMap structs and delete global references used in cached values.
 */
void free_enum_map(JNIEnv* env, EnumMap** ref)
{
    EnumMap* enum_map = *ref;
    for (int i = 0; i < enum_map -> max_value; i++)
    {
        if (!enum_map -> values[i]) continue;
        (*env) -> DeleteGlobalRef(env, enum_map -> values[i]);
    }
    (*env) -> DeleteGlobalRef(env, enum_map -> clazz);
    free(enum_map -> values);
    free(enum_map);

    ref = NULL;
}

/**
 * Clean memory on unloading
 */
void JNI_OnUnload(JavaVM *vm, void *reserved)
{
    JNIEnv* env = getEnv(vm);

    // delete global referencies
    (*env) -> DeleteGlobalRef(env, attls_context_clazz);
    (*env) -> DeleteGlobalRef(env, enum_protocol_clazz);

    // free EnumMap structs
    free_enum_map(env, stat_policy_enum_map);
    free_enum_map(env, stat_conn_enum_map);
    free_enum_map(env, security_type_enum_map);
    free_enum_map(env, fips140_enum_map);
}
