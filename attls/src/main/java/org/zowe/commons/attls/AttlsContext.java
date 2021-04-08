/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package org.zowe.commons.attls;

/**
 * This class publish all AT-TLS information about the session. As input are two parameters:
 * - id - id of filedescription to attach right session
 * - alwaysLoadCertificate - define, if certificate should be fetch together with basic information. It can save one
 * more call of IOCTL in case certificate is always required. Otherwise library fetch certificate only if you call
 * method getCertificate.
 * <p>
 * This context read value lazy, it means that until you call any method, no data are fetched. In case of getting any
 * information, library make call on first time to query or certificate and cache them in internal block of bytes
 * (see {@link AttlsContext#ioctl}. All java object are then created just once time and store into cache properties.
 * Next calling returns only those cached value. If you want to fetch new data, you should call method
 * {@link AttlsContext#clean()}.
 * <p>
 * For fetching a certificate is needed to prepare memory before, its size is defined by
 * {@link AttlsContext#BUFFER_CERTIFICATE_LENGTH}.
 */
public class AttlsContext {

    /**
     * Name of native library
     */
    public static final String ATTLS_LIBRARY_NAME = "zowe-attls";
    /**
     * Size of buffer to fetch certificate
     */
    private static final int BUFFER_CERTIFICATE_LENGTH = 10240;

    static {
        if ("z/os".equalsIgnoreCase(System.getProperty("os.name"))) {
            System.loadLibrary(ATTLS_LIBRARY_NAME);
        }
    }

    /**
     * Control flag to identify if certificate should be fetch in each query call or not
     */
    private boolean alwaysLoadCertificate;

    /**
     * FileDescriptior of socket
     */
    private int id;
    /**
     * Request memory data
     */
    private byte[] ioctl;
    /**
     * Buffer for storing certificate
     */
    private byte[] bufferCertificate;

    /**
     * true if query data are loaded
     */
    private boolean queryLoaded;
    /**
     * true if certificate is loaded
     */
    private boolean certificateLoaded;

    /**
     * cache for loaded values from ioctl
     */
    private StatPolicy statPolicyCache;
    private StatConn statConnCache;
    private Protocol protocolCache;
    private String negotiatedCipher2Cache;
    private SecurityType securityTypeCache;
    private String userIdCache;
    private Fips140 fips140Cache;
    private String negotiatedCipher4Cache;
    private String negotiatedKeyShareCache;
    private byte[] certificateCache;

    /**
     * Create context of socket identified by FileDescriptor id ({@link java.io.FileDescriptor},
     * {@link sun.nio.ch.IOUtil#fdVal(java.io.FileDescriptor)}).
     *
     * @param id                    filedescriptor of socket
     * @param alwaysLoadCertificate if set true, first query call will fetch also a certificate, otherwise it will be
     *                              loaded in first call of {@link AttlsContext#getCertificate}
     */
    public AttlsContext(int id, boolean alwaysLoadCertificate) {
        this.id = id;
        this.alwaysLoadCertificate = alwaysLoadCertificate;
    }

    /**
     * Clean all cached value. Next call will fetch new data via ioctl.
     */
    public native void clean();

    /**
     * Indicates the policy status for the connection at the time of policy lookup always returned (except in error cases)
     *
     * @return policy status
     * @throws UnknownEnumValueException StatPolicy does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException        unexpected error in call of ioctl
     */
    public native StatPolicy getStatPolicy() throws UnknownEnumValueException, IoctlCallException;

    /**
     * Indicates the security status for the connection - always returned (except in error cases)
     *
     * @return security status
     * @throws UnknownEnumValueException StatConn does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException        unexpected error in call of ioctl
     */
    public native StatConn getStatConn() throws UnknownEnumValueException, IoctlCallException;

    /**
     * Indicates the SSL protocol in use for the connection. If connection is not secure, returns
     * {@link Protocol#NON_SECURE}
     *
     * @return SSL protocol
     * @throws UnknownEnumValueException Protocol does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException        unexpected error in call of ioctl
     */
    public native Protocol getProtocol() throws UnknownEnumValueException, IoctlCallException;

    /**
     * Indicates the negotiated cipher in use for the connection - returned when connection is secure
     * Note: When the negotiated cipher requires four characters, this field will contain the characters '4X'.
     * {@link org.zowe.commons.attls.AttlsContext#getNegotiatedCipher4()}
     *
     * @return negotiated cipher in use (2 character)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public native String getNegotiatedCipher2() throws IoctlCallException;

    /**
     * Indicates the security type for the connection - returned when policy defined for connection
     *
     * @return the security type for the connection
     * @throws UnknownEnumValueException Protocol does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException        unexpected error in call of ioctl
     */
    public native SecurityType getSecurityType() throws UnknownEnumValueException, IoctlCallException;

    /**
     * Indicates the partner user ID - returned when available.
     *
     * @return partner user ID
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public native String getUserId() throws IoctlCallException;

    /**
     * Indicates the level of FIPS compliance, if any - returned when connection is secure for connection
     *
     * @return level of FIPS compliance
     * @throws UnknownEnumValueException Protocol does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException        unexpected error in call of ioctl
     */
    public native Fips140 getFips140() throws UnknownEnumValueException, IoctlCallException;

    /**
     * Reserved for IBM use
     * <p>
     * Constants for TTLSi_Flags:
     * TTLS_FTPDATACONN            0x01
     *
     * @return AT-TLS flags
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public native byte getFlags() throws IoctlCallException;

    /**
     * Indicates the four character negotiated cipher in use for the connection - returned when connection is secure
     *
     * @return negotiated cipher in use (4 character)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public native String getNegotiatedCipher4() throws IoctlCallException;

    /**
     * Indicates the four character negotiated key share in use for the connection - returned when the connection is
     * secure and the protocol in use is TLS 1.3 or later
     *
     * @return four character negotiated key share in use for the connection
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public native String getNegotiatedKeyShare() throws IoctlCallException;

    /**
     * Returns partner certificate - returned when available. Maximum length of certificate is determinated by
     * {@link AttlsContext#BUFFER_CERTIFICATE_LENGTH}
     *
     * @return partner certificate
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public native byte[] getCertificate() throws IoctlCallException;

    /**
     * Initialize the SSL connection
     *
     * @throws IoctlCallException cannot initialize (ie. not in controlled mode, missing configuration etc.)
     */
    public native void initConnection() throws IoctlCallException;

    /**
     * Reset the Session
     *
     * @throws IoctlCallException cannot reset session (ie. not in controlled mode, missing configuration etc.)
     */
    public native void resetSession() throws IoctlCallException;

    /**
     * Reset the Cipher
     *
     * @throws IoctlCallException cannot reset cipher (ie. not in controlled mode, missing configuration etc.)
     */
    public native void resetCipher() throws IoctlCallException;

    /**
     * Stop the SSL connection
     *
     * @throws IoctlCallException cannot stop connection (ie. not in controlled mode, missing configuration etc.)
     */
    public native void stopConnection() throws IoctlCallException;

    /**
     * Allow SSL handshake to timeout
     *
     * @throws IoctlCallException cannot allow hand shake timeout (ie. not in controlled mode, missing configuration etc.)
     */
    public native void allowHandShakeTimeout() throws IoctlCallException;

    /**
     * Reset the write cipher (TLSv1.3 or later)
     *
     * @throws IoctlCallException cannot reset write cipher (ie. not in controlled mode, missing configuration etc.)
     */
    public native void resetWriteCipher() throws IoctlCallException;

    /**
     * Send session ticket (TLSv1.3 or later)
     *
     * @throws IoctlCallException cannot send session ticket (ie. not in controlled mode, missing configuration etc.)
     */
    public native void sendSessionTicket() throws IoctlCallException;

}
