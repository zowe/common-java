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
const char *JNI_CLASS_OUT_OF_MEMORY_ERROR = "java/lang/OutOfMemoryError";

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
const char *MESSAGE_CANNOT_MALLOC = "Not enough space to allocate memory in native code";

/**
 * signatures to get method Arrays.fill - clean up of arrays
 */
const char *JNI_SIGNATURE_ARRAYS = "java/util/Arrays";
const char *JNI_SIGNATURE_ARRAYS_FILL = "fill";
const char *JNI_SIGNATURE_METHOD_BYTE_ARRAY_BYTE_VOID = "([BB)V";

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
 * The DTO collecting basic references about buffers and control values.
 */
typedef struct context {
    jint socket_id;

    jbyteArray ioctl_array;
    struct TTLS_IOCTL* ioctl_buffer;

    jboolean load_certificate;
    jbyteArray certificate_array;
    char* certificate_buffer;
    int certificate_buffer_length;
} Context;

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
 * Class Arrays and method Arrays.fill(byte[], byte) to clean byte arrays
 */
jclass arraysClass;
jmethodID arrays_fill_method_ID;

/**
 * Exception handling
 */
jclass outOfMemoryErrorClazz;
jclass ioctl_call_exception_clazz;
jmethodID ioctl_call_exception_constructor;
jclass illegal_argument_exception_clazz;
jclass unknown_enum_value_exception_clazz;
jmethodID unknown_enum_value_exception_constructor;
jmethodID unknown_enum_value_exception_constructor2;

int strnlen(char *txt, int max) {
    if (max < 0) return 0;
    for (int i = 0; i < max; i++) {
        if (!txt[i]) return i;
    }
    return max;
}

/**
 * throw and OutOfMemoryError
 */
void throw_out_of_memory(JNIEnv *env)
{
    (*env) -> ThrowNew(env, outOfMemoryErrorClazz, MESSAGE_CANNOT_MALLOC);
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
    char *output = (char*) malloc(length + 1);
    if (!output) {
        throw_out_of_memory(env);
        return NULL;
    }
    strncpy(output, ebcdic, length);
    output[length] = 0;

    int size = __etoa(output);
    if (size < 0) {
        (*env) -> ThrowNew(env, illegal_argument_exception_clazz, JNI_MESSAGE_CANNOT_CONVERT_USER_ID);
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
    char* signature = (char*) malloc(
        strlen(clazz) +
        strlen(JNI_SIGNATURE_METHOD_NONE_ARRAY_PREFIX) +
        strlen(JNI_SIGNATURE_METHOD_SEMICOLON_SUFFIX) +
        1
    );
    if (!signature) {
        throw_out_of_memory(env);
        return NULL;
    }
    strcpy(signature, JNI_SIGNATURE_METHOD_NONE_ARRAY_PREFIX);
    strcat(signature, clazz);
    strcat(signature, JNI_SIGNATURE_METHOD_SEMICOLON_SUFFIX);

    // call static method <Enum>.values()
    jclass enum_clazz = (*env) -> FindClass(env, clazz);
    jmethodID method_values = (*env) -> GetStaticMethodID(env, enum_clazz, JNI_METHOD_VALUES, signature);
    jobjectArray values = (*env) -> CallStaticObjectMethod(env, enum_clazz, method_values);

    free(signature);

    // find method byte <Enum>.getValue()
    jmethodID method_get_value = (*env) -> GetMethodID(env, enum_clazz, JNI_METHOD_GET_VALUE, JNI_SIGNATURE_METHOD_NONE_BYTE);

    // find the highest value
    jbyte max_value = 0;
    int count = (*env) -> GetArrayLength(env, values);
    for (int i = 0; i < count; i++) {
        jclass item = (*env) -> GetObjectArrayElement(env, values, i);
        jbyte value = (*env) -> CallByteMethod(env, item, method_get_value);
        if (value > max_value) max_value = value;
        (*env) -> DeleteLocalRef(env, item);
    }

    // construct struct EnumMap with empty values
    EnumMap* out = (EnumMap*) malloc(sizeof(EnumMap));
    if (!out) {
        throw_out_of_memory(env);
        return NULL;
    }
    out -> max_value = (int) max_value;
    out -> clazz = (*env) -> NewGlobalRef(env, enum_clazz);
    out -> clazzName = clazz;
    int array_size = (max_value + 1) * sizeof(jobject*);
    out -> values = (jobject*) malloc(array_size);
    if (!out -> values) {
        throw_out_of_memory(env);
        return NULL;
    }
    memset(out -> values, 0, array_size);

    // fill values in the array
    for (int i = 0; i < count; i++) {
        jobject item = (*env) -> GetObjectArrayElement(env, values, i);
        jbyte value = (*env) -> CallByteMethod(env, item, method_get_value);
        out -> values[value] = (*env) -> NewGlobalRef(env, item);
        (*env) -> DeleteLocalRef(env, item);
    }

    return out;
}

/**
 * Throws UnknownEnumValueException with set values
 */
void throw_unknown_enum_value(JNIEnv *env, EnumMap* enum_map, unsigned char value) {
    jobject exception = (*env) -> NewObject(env, unknown_enum_value_exception_clazz, unknown_enum_value_exception_constructor, enum_map -> clazz, (jbyte) value);
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
    (*vm) -> GetEnv(vm, (void**) &env, JNI_VERSION);
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
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    attls_context_clazz = (*env) -> NewGlobalRef(env, clazz);

    // fetch size of certificate length
    jfieldID buffer_certificate_size_field = (*env) -> GetStaticFieldID(env, clazz, JNI_PROPERTY_BUFFER_CERTIFICATE_LENGTH, JNI_SIGNATURE_PROPERTY_INTEGER);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    buffer_certificate_size = (*env) -> GetStaticIntField(env, clazz, buffer_certificate_size_field);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;

    // fetch all fields to properties of AttlsContext
    always_load_certificate_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_ALWAYS_LOAD_CERTIFICATE, JNI_SIGNATURE_PROPERTY_BOOLEAN);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    id_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_ID, JNI_SIGNATURE_PROPERTY_INTEGER);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    ioctl_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_IOCTL, JNI_SIGNATURE_PROPERTY_BYTE_ARRAY);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    buffer_certificate_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_BUFFER_CERTIFICATE, JNI_SIGNATURE_PROPERTY_BYTE_ARRAY);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    query_loaded_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_QUERY_LOADED, JNI_SIGNATURE_PROPERTY_BOOLEAN);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    certificate_loaded_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_CERTIFICATE_LOADED, JNI_SIGNATURE_PROPERTY_BOOLEAN);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    stat_policy_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_STAT_POLICY_CACHE, JNI_SIGNATURE_PROPERTY_STAT_POLICY);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    stat_conn_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_STAT_CONN_CACHE, JNI_SIGNATURE_PROPERTY_STAT_CONN);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    protocol_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_PROTOCOL_CACHE, JNI_SIGNATURE_PROPERTY_PROTOCOL);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    negotiated_cipher2_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_NEGOTIATED_CIPHER_2_CACHE, JNI_SIGNATURE_PROPERTY_STRING);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    security_type_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_SECURITY_TYPE_CACHE, JNI_SIGNATURE_PROPERTY_SECURITY_TYPE);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    user_id_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_USER_ID_CACHE, JNI_SIGNATURE_PROPERTY_STRING);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    fips140_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_FIPS_140_CACHE, JNI_SIGNATURE_PROPERTY_FIPS_140);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    negotiated_cipher4_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_NEGOTIATED_CIPHER_4_CACHE, JNI_SIGNATURE_PROPERTY_STRING);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    negotiated_key_share_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_NEGOTIATED_KEY_SHARE_CACHE, JNI_SIGNATURE_PROPERTY_STRING);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    certificate_cache_field = (*env) -> GetFieldID(env, clazz, JNI_PROPERTY_CERTIFICATE_CACHE, JNI_SIGNATURE_PROPERTY_BYTE_ARRAY);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;

    // prepare EnumMap for all possible relevant enumerations
    stat_policy_enum_map = load_enum_map(env, JNI_CLASS_STAT_POLICY);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    stat_conn_enum_map = load_enum_map(env, JNI_CLASS_STAT_CONN);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    security_type_enum_map = load_enum_map(env, JNI_CLASS_SECURITY_TYPE);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    fips140_enum_map = load_enum_map(env, JNI_CLASS_FIPS_140);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;

    // fetch Protocol.class and method Protocol.values() - cannot use EnumMap (it has 2 bytes to identify)
    enum_protocol_clazz = (*env) -> NewGlobalRef(env, (*env) -> FindClass(env, JNI_CLASS_PROTOCOL));
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    protocol_value_of_method_ID = (*env) -> GetStaticMethodID(env, enum_protocol_clazz, JNI_METHOD_VALUE_OF, JNI_SIGNATURE_METHOD_BYTE_BYTE_PROTOCOL);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;

    // find method Arrays.fill for byte array clean up
    arraysClass = (*env) -> NewGlobalRef(env, (*env) -> FindClass(env, JNI_SIGNATURE_ARRAYS));
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    arrays_fill_method_ID = (*env) -> GetStaticMethodID(env, arraysClass, JNI_SIGNATURE_ARRAYS_FILL, JNI_SIGNATURE_METHOD_BYTE_ARRAY_BYTE_VOID);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;

    // fetch reference to exceptions
    outOfMemoryErrorClazz = (*env) -> NewGlobalRef(env, (*env) -> FindClass(env, JNI_CLASS_OUT_OF_MEMORY_ERROR));
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    ioctl_call_exception_clazz = (*env) -> NewGlobalRef(env, (*env) -> FindClass(env, JNI_CLASS_IOCTL_CALL_EXCEPTION));
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    ioctl_call_exception_constructor = (*env) -> GetMethodID(env, ioctl_call_exception_clazz, JNI_METHOD_CONSTRUCTOR, JNI_SIGNATURE_METHOD_INT_INT_INT_VOID);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    illegal_argument_exception_clazz = (*env) -> NewGlobalRef(env, (*env) -> FindClass(env, JNI_CLASS_ILLEGAL_ARGUMENT_EXCEPTION));
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    unknown_enum_value_exception_clazz = (*env) -> NewGlobalRef(env, (*env) -> FindClass(env, JNI_CLASS_UNKNOWN_ENUM_VALUE_EXCEPTION));
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    unknown_enum_value_exception_constructor = (*env) -> GetMethodID(env, unknown_enum_value_exception_clazz, JNI_METHOD_CONSTRUCTOR, JNI_SIGNATURE_METHOD_ENUM_BYTE_VOID);
    if ((*env) -> ExceptionCheck(env)) return JNI_VERSION;
    unknown_enum_value_exception_constructor2 = (*env) -> GetMethodID(env, unknown_enum_value_exception_clazz, JNI_METHOD_CONSTRUCTOR, JNI_SIGNATURE_METHOD_ENUM_BYTE_BYTE_VOID);

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
 * Methods clean up the byte array in AttlsContext if exists
 */
void cleanByteArray(JNIEnv *env, jobject obj, jfieldID arrayField, jboolean setNull)
{
    jbyteArray arr = (*env) -> GetObjectField(env, obj, arrayField);
    if (arr) {
        (*env) -> CallStaticVoidMethod(env, arraysClass, arrays_fill_method_ID, arr, (jbyte) 0);
        if (setNull) {
            (*env) -> SetObjectField(env, obj, arrayField, NULL);
        }
        (*env) -> DeleteLocalRef(env, arr);
    }
}

/**
 * The method read buffers from AttlsContext. If any is not created, it create a new one. The method returns DTO Context
 * that contains all related pointers. It is necessary to call method releaseContext before leaving the JNI code.
 *
 * env - JNI environment (from the original JNI call)
 * obj - instance of AttlsContext (from the original JNI call)
 * certificate - if true method will allocate also buffer for reading certificate
 * erase - if true the buffers will be empty - before a new call is a good practice to cleanup buffers
 */
Context *getContext(JNIEnv *env, jobject obj, jboolean loadCertificate, jboolean erase)
{
    Context *c = (Context*) malloc(sizeof(Context));
    if (!c) {
        throw_out_of_memory(env);
        return NULL;
    }

    // flags to indicate if created buffers are already empty (see new array created by Java) - to reduce memset calls
    jboolean emptyIoctlArray = JNI_FALSE;
    jboolean emptyCertificateArray = JNI_FALSE;

    // obtain socket ID from AttlsContext class
    c -> socket_id = (*env) -> GetIntField(env, obj, id_field);

    // obtain IOCTL object or create new one
    jbyteArray ioctlArray = (*env) -> GetObjectField(env, obj, ioctl_field);
    if (!ioctlArray) {
        ioctlArray = (*env) -> NewByteArray(env, sizeof(struct TTLS_IOCTL));
        (*env) -> SetObjectField(env, obj, ioctl_field, ioctlArray);
        emptyIoctlArray = JNI_TRUE;
    }
    c -> ioctl_array = ioctlArray;
    c -> ioctl_buffer = (struct TTLS_IOCTL*) (*env) -> GetByteArrayElements(env, ioctlArray, 0);

    if (erase && !emptyIoctlArray) {
        memset(c -> ioctl_buffer, 0, sizeof(struct TTLS_IOCTL));
    }

    // obtain certificate buffer or create new one if needed
    c -> load_certificate = loadCertificate;
    if (!loadCertificate) {
        c -> load_certificate = (*env) -> GetBooleanField(env, obj, always_load_certificate_field);
    }
    if (c -> load_certificate) {
        jbyteArray certArray = (*env) -> GetObjectField(env, obj, buffer_certificate_field);
        if (!certArray) {
            certArray = (*env) -> NewByteArray(env, buffer_certificate_size);
            (*env) -> SetObjectField(env, obj, buffer_certificate_field, certArray);
            emptyCertificateArray = JNI_TRUE;
        }
        c -> certificate_array = certArray;
        c -> certificate_buffer = (*env) -> GetByteArrayElements(env, certArray, 0);
        c -> certificate_buffer_length = buffer_certificate_size;

        if (erase && !emptyCertificateArray) {
            memset(c -> certificate_buffer, 0, buffer_certificate_size);
        }
    } else {
        c -> certificate_array = NULL;
        c -> certificate_buffer = NULL;
        c -> certificate_buffer_length = 0;

        if (erase) {
            // current call does not require certificate buffer, but it maybe exists. Clean up it for a next call
            cleanByteArray(env, obj, buffer_certificate_field, JNI_FALSE);
        }
    }

    return c;
}

/**
 * Methods to release native buffers, local references and DTO Context
 */
void releaseContext(JNIEnv *env, Context *c)
{
    if (!c) {
        return;
    }

    (*env) -> ReleaseByteArrayElements(env, c -> ioctl_array, (jbyte*) c -> ioctl_buffer, 0);
    (*env) -> DeleteLocalRef(env, c -> ioctl_array);

    if (c -> load_certificate) {
        (*env) -> ReleaseByteArrayElements(env, c -> certificate_array, (jbyte*) c -> certificate_buffer, 0);
        (*env) -> DeleteLocalRef(env, c -> certificate_array);
    }

    free(c);
}

/**
 * It call ioctl to fetch query or certificate. Query call is done always, the certificate is loaded just if argument
 * certificate is set to true or alwaysLoadCertificate is set to true.
 * In case of an error during fetching data IoctlCallException is thrown.
 */
Context* query(JNIEnv *env, jobject obj, jboolean certificate)
{
    // get struct of request
    struct context* c = getContext(env, obj, certificate, JNI_TRUE);
    if (!c) {
        return NULL;
    }

    // construct request
    c -> ioctl_buffer -> TTLSi_Ver = TTLS_VERSION1;
    c -> ioctl_buffer -> TTLSi_Req_Type = TTLS_QUERY_ONLY;
    if (c -> load_certificate) {
        c -> ioctl_buffer -> TTLSi_Req_Type |= TTLS_RETURN_CERTIFICATE;
    }

    c -> ioctl_buffer -> TTLSi_BufferPtr = c -> certificate_buffer;
    c -> ioctl_buffer -> TTLSi_BufferLen = c -> certificate_buffer_length;

    // call ioctl
    int rcIoctl = ioctl(c -> socket_id, SIOCTTLSCTL, c -> ioctl_buffer);

    if (rcIoctl < 0) {
        // if ioctl returns an error throw exception
        jobject exception = (*env) -> NewObject(env, ioctl_call_exception_clazz, ioctl_call_exception_constructor,
            (jint) rcIoctl, (jint) errno, (jint) __errno2());
        (*env) -> Throw(env, exception);
    } else {
        // update fields queryLoaded and certificateLoaded to avoid unnecessary call of IOCTL next time
        (*env) -> SetBooleanField(env, obj, query_loaded_field, JNI_TRUE);
        if (c -> load_certificate) {
            (*env) -> SetBooleanField(env, obj, certificate_loaded_field, JNI_TRUE);
        }
    }

    return c;
}

/**
 * Return ioctl with data from query call. If data are available in memory, returns them, otherwise call ioctl.
 * If alwaysLoadCertificate is set to true certificated is also fetched.
 */
Context* requireQuery(JNIEnv *env, jobject obj)
{
    if (isQueryLoaded(env, obj)) {
        // query was done, just read the buffers
        return getContext(env,obj, JNI_FALSE, JNI_FALSE);
    }

    // issue a new query with erased buffers
    return query(env, obj, JNI_FALSE);
}

/**
 * Return ioctl with data with certificate. If data are available in memory, returns them, otherwise call ioctl.
 */
Context* requireCertificate(JNIEnv *env, jobject obj)
{
    if (isCertificateLoaded(env, obj)) {
        // query with certificate was done, just read the buffers
        return getContext(env, obj, JNI_TRUE, JNI_FALSE);
    }

    // issue a new query with erased buffers
    return query(env, obj, JNI_TRUE);
}

/**
 * Clean state of AttlsContext. It remove all cached data. Next call will fetch new one.
 */
JNIEXPORT void JNICALL Java_org_zowe_commons_attls_AttlsContext_clean(JNIEnv *env, jobject obj)
{
    // clean flags about loaded data
    (*env) -> SetBooleanField(env, obj, query_loaded_field, JNI_FALSE);
    (*env) -> SetBooleanField(env, obj, certificate_loaded_field, JNI_FALSE);

    // clean all bytearrays
    cleanByteArray(env, obj, ioctl_field, JNI_TRUE);
    cleanByteArray(env, obj, buffer_certificate_field, JNI_TRUE);
    cleanByteArray(env, obj, certificate_cache_field, JNI_TRUE);

    // clean all (non-array) cached values (Java objects)
    (*env) -> SetObjectField(env, obj, stat_policy_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, stat_conn_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, protocol_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, negotiated_cipher2_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, security_type_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, user_id_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, fips140_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, negotiated_cipher4_cache_field, NULL);
    (*env) -> SetObjectField(env, obj, negotiated_key_share_cache_field, NULL);
}

/**
 * Return or load and cache value AttlsContext.statPolicyCache
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getStatPolicy(JNIEnv *env, jobject obj)
{
    jobject out = (*env) -> GetObjectField(env, obj, stat_policy_cache_field);
    if (out) return out;

    Context* c = requireQuery(env, obj);
    if (! ((*env) -> ExceptionCheck(env))) {
        out = get_enum(env, stat_policy_enum_map, c -> ioctl_buffer -> TTLSi_Stat_Policy);
        if (! ((*env) -> ExceptionCheck(env))) {
            (*env) -> SetObjectField(env, obj, stat_policy_cache_field, out);
        }
    }
    releaseContext(env, c);

    return out;
}

/**
 * Return or load and cache value AttlsContext.statConnCache
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getStatConn(JNIEnv *env, jobject obj)
{
    jobject out = (*env) -> GetObjectField(env, obj, stat_conn_cache_field);
    if (out) return out;

    Context* c = requireQuery(env, obj);
    if (! ((*env) -> ExceptionCheck(env))) {
        out = get_enum(env, stat_conn_enum_map, c -> ioctl_buffer -> TTLSi_Stat_Conn);
        if (! ((*env) -> ExceptionCheck(env))) {
            (*env) -> SetObjectField(env, obj, stat_conn_cache_field, out);
        }
    }
    releaseContext(env, c);

    return out;
}

/**
 * Return or load and cache value AttlsContext.protocolCache
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getProtocol(JNIEnv *env, jobject obj)
{
    jobject out = (*env) -> GetObjectField(env, obj, protocol_cache_field);
    if (out) return out;

    Context* c = requireQuery(env, obj);
    if (! ((*env) -> ExceptionCheck(env))) {
        out = (*env) -> CallStaticObjectMethod(env, enum_protocol_clazz, protocol_value_of_method_ID,
            (jbyte) c -> ioctl_buffer -> TTLSi_SSL_Protocol.Prot_bytes.Prot_Ver,
            (jbyte) c -> ioctl_buffer -> TTLSi_SSL_Protocol.Prot_bytes.Prot_Mod);
        if (!out) {
            // if enum was not fetched, throw exception
            jobject exception = (*env) -> NewObject(env, unknown_enum_value_exception_clazz, unknown_enum_value_exception_constructor2, enum_protocol_clazz,
                (jbyte) c -> ioctl_buffer -> TTLSi_SSL_Protocol.Prot_bytes.Prot_Ver,
                (jbyte) c -> ioctl_buffer -> TTLSi_SSL_Protocol.Prot_bytes.Prot_Mod);
            (*env) -> Throw(env, exception);
        }
    }
    releaseContext(env, c);

    return out;
}

/**
 * Return or load and cache value AttlsContext.negotiatedCipher2Cache
 */
JNIEXPORT jstring JNICALL Java_org_zowe_commons_attls_AttlsContext_getNegotiatedCipher2(JNIEnv *env, jobject obj)
{
    jstring out = (*env) -> GetObjectField(env, obj, negotiated_cipher2_cache_field);
    if (out) return out;

    Context* c = requireQuery(env, obj);
    if (! ((*env) -> ExceptionCheck(env))) {
        out = get_jstring(env, c -> ioctl_buffer -> TTLSi_Neg_Cipher, 2);
        if (! ((*env) -> ExceptionCheck(env))) {
            (*env) -> SetObjectField(env, obj, negotiated_cipher2_cache_field, out);
        }
    }
    releaseContext(env, c);

    return out;
}

/**
 * Return or load and cache value AttlsContext.securityTypeCache
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getSecurityType(JNIEnv *env, jobject obj)
{
    jobject out = (*env) -> GetObjectField(env, obj, security_type_cache_field);
    if (out) return out;

    Context* c = requireQuery(env, obj);
    if (! ((*env) -> ExceptionCheck(env))) {
        out = get_enum(env, security_type_enum_map, c -> ioctl_buffer -> TTLSi_Sec_Type);
        if (! ((*env) -> ExceptionCheck(env))) {
            (*env) -> SetObjectField(env, obj, security_type_cache_field, out);
        }
    }
    releaseContext(env, c);

    return out;
}

/**
 * Return or load and cache value AttlsContext.statPolicyCache
 */
JNIEXPORT jstring JNICALL Java_org_zowe_commons_attls_AttlsContext_getUserId(JNIEnv *env, jobject obj)
{
    jstring out = (*env) -> GetObjectField(env, obj, user_id_cache_field);
    if (out) return out;

    Context* c = requireQuery(env, obj);
    if (! ((*env) -> ExceptionCheck(env))) {
        out = get_jstring(env, c -> ioctl_buffer  -> TTLSi_UserID, c -> ioctl_buffer -> TTLSi_UserID_Len);
        if (! ((*env) -> ExceptionCheck(env))) {
            (*env) -> SetObjectField(env, obj, user_id_cache_field, out);
        }
    }
    releaseContext(env, c);

    return out;
}

/**
 * Return or load and cache value AttlsContext.fips140Cache
 */
JNIEXPORT jobject JNICALL Java_org_zowe_commons_attls_AttlsContext_getFips140(JNIEnv *env, jobject obj)
{
    jobject out = (*env) -> GetObjectField(env, obj, fips140_cache_field);
    if (out) return out;

    Context* c = requireQuery(env, obj);
    if (! ((*env) -> ExceptionCheck(env))) {
        out = get_enum(env, fips140_enum_map, c -> ioctl_buffer -> TTLSi_FIPS140);
        if (! ((*env) -> ExceptionCheck(env))) {
            (*env) -> SetObjectField(env, obj, fips140_cache_field, out);
        }
    }
    releaseContext(env, c);

    return out;
}

/**
 * Return or load value flag
 */
JNIEXPORT jbyte JNICALL Java_org_zowe_commons_attls_AttlsContext_getFlags(JNIEnv *env, jobject obj)
{
    Context* c = requireQuery(env, obj);
    jbyte out = 0;
    if (! ((*env) -> ExceptionCheck(env))) {
        out = (jbyte) c -> ioctl_buffer -> TTLSi_Flags;
    }
    releaseContext(env, c);
    return out;
}

/**
 * Return or load and cache value AttlsContext.negotiatedCipher4Cache
 */
JNIEXPORT jstring JNICALL Java_org_zowe_commons_attls_AttlsContext_getNegotiatedCipher4(JNIEnv *env, jobject obj)
{
    jstring out = (*env) -> GetObjectField(env, obj, negotiated_cipher4_cache_field);
    if (out) return out;

    Context* c = requireQuery(env, obj);
    if (! ((*env) -> ExceptionCheck(env))) {
        out = get_jstring(env, c -> ioctl_buffer -> TTLSi_Neg_Cipher4, 4);
        if (! ((*env) -> ExceptionCheck(env))) {
            (*env) -> SetObjectField(env, obj, negotiated_cipher4_cache_field, out);
        }
    }
    releaseContext(env, c);

    return out;
}

/**
 * Return or load and cache value AttlsContext.certificateCache
 */
JNIEXPORT jbyteArray JNICALL Java_org_zowe_commons_attls_AttlsContext_getCertificate(JNIEnv *env, jobject obj)
{
    jbyteArray out = (*env) -> GetObjectField(env, obj, certificate_cache_field);
    if (out) return out;

    Context* c = requireCertificate(env, obj);
    if (! ((*env) -> ExceptionCheck(env))) {
        out = (*env) -> NewByteArray(env, c -> ioctl_buffer -> TTLSi_Cert_Len);
        (*env) -> SetByteArrayRegion(env, out, 0, c -> ioctl_buffer -> TTLSi_Cert_Len, c -> ioctl_buffer -> TTLSi_BufferPtr);
        (*env) -> SetObjectField(env, obj, certificate_cache_field, out);
    }
    releaseContext(env, c);

    return out;
}

/**
 * This method call ioctl with request type by argument command. It is using to call other request type than query and
 * protocol (They are called via method load).
 */
void issueCommand(JNIEnv *env, jobject obj, int command)
{
    Context* c = getContext(env, obj, JNI_FALSE, JNI_TRUE);
    if (!c) {
        return;
    }

    // previous fetched data about state and certificate were forgotten. They could be also change because of the command
    (*env) -> SetBooleanField(env, obj, query_loaded_field, JNI_FALSE);
    (*env) -> SetBooleanField(env, obj, certificate_loaded_field, JNI_FALSE);

    c -> ioctl_buffer -> TTLSi_Ver = TTLS_VERSION1;
    c -> ioctl_buffer -> TTLSi_Req_Type = command;
    c -> ioctl_buffer -> TTLSi_BufferPtr = NULL;
    c -> ioctl_buffer -> TTLSi_BufferLen = 0;

    int rcIoctl = ioctl(c -> socket_id, SIOCTTLSCTL, c -> ioctl_buffer);
    releaseContext(env, c);

    if (rcIoctl < 0) {
        jobject exception = (*env) -> NewObject(env, ioctl_call_exception_clazz, ioctl_call_exception_constructor,
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

/**
 * Free memory using for EnumMap structs and delete global references used in cached values.
 */
void free_enum_map(JNIEnv* env, EnumMap* enum_map)
{
    for (int i = 0; i < enum_map -> max_value; i++) {
        if (!enum_map -> values[i]) continue;
        (*env) -> DeleteGlobalRef(env, enum_map -> values[i]);
    }
    (*env) -> DeleteGlobalRef(env, enum_map -> clazz);
    free(enum_map -> values);
    free(enum_map);
}

/**
 * Clean memory on unloading
 */
void JNI_OnUnload(JavaVM *vm, void *reserved)
{
    JNIEnv* env = getEnv(vm);

    // delete global references
    (*env) -> DeleteGlobalRef(env, attls_context_clazz);
    (*env) -> DeleteGlobalRef(env, enum_protocol_clazz);
    (*env) -> DeleteGlobalRef(env, arraysClass);

    // free EnumMap structs
    free_enum_map(env, stat_policy_enum_map);
    free_enum_map(env, stat_conn_enum_map);
    free_enum_map(env, security_type_enum_map);
    free_enum_map(env, fips140_enum_map);
}
