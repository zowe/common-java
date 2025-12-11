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

public interface AttlsContext {

    /**
     * Name of native library
     */
    String ATTLS_LIBRARY_NAME = "bcm-apisdk-attls";

    /**
     * Clean all cached value. Next call will fetch new data via ioctl.
     */
    void clean();

    /**
     * Indicates the policy status for the connection at the time of policy lookup always returned (except in error cases)
     * @return policy status
     * @throws UnknownEnumValueException StatPolicy does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    StatPolicy getStatPolicy() throws UnknownEnumValueException, IoctlCallException;

    /**
     * Indicates the security status for the connection - always returned (except in error cases)
     * @return security status
     * @throws UnknownEnumValueException StatConn does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    StatConn getStatConn() throws UnknownEnumValueException, IoctlCallException;

    /**
     * Indicates the SSL protocol in use for the connection. If connection is not secure, returns
     * {@link Protocol#NON_SECURE}
     * @return SSL protocol
     * @throws UnknownEnumValueException Protocol does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    Protocol getProtocol() throws UnknownEnumValueException, IoctlCallException;

    /**
     * Indicates the negotiated cipher in use for the connection - returned when connection is secure
     * Note: When the negotiated cipher requires four characters, this field will contain the characters '4X'.
     *       {@link AttlsContext#getNegotiatedCipher4()}
     * @return negotiated cipher in use (2 character)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    String getNegotiatedCipher2() throws IoctlCallException;

    /**
     * Indicates the security type for the connection - returned when policy defined for connection
     * @return the security type for the connection
     * @throws UnknownEnumValueException Protocol does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    SecurityType getSecurityType() throws UnknownEnumValueException, IoctlCallException;

    /**
     * Indicates the partner user ID - returned when available.
     * @return partner user ID
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    String getUserId() throws IoctlCallException;

    /**
     * Indicates the level of FIPS compliance, if any - returned when connection is secure for connection
     * @return level of FIPS compliance
     * @throws UnknownEnumValueException Protocol does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    Fips140 getFips140() throws UnknownEnumValueException, IoctlCallException;

    /**
     * Reserved for IBM use
     *
     * Constants for TTLSi_Flags:
     *      TTLS_FTPDATACONN            0x01
     *
     * @return AT-TLS flags
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    byte getFlags() throws IoctlCallException;

    /**
     * Indicates the four character negotiated cipher in use for the connection - returned when connection is secure
     * @return negotiated cipher in use (4 character)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    String getNegotiatedCipher4() throws IoctlCallException;

    /**
     * Returns partner certificate - returned when available. Maximum length of certificate is determinated by
     * {@link AttlsContextImpl#BUFFER_CERTIFICATE_LENGTH}
     * @return partner certificate
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    byte[] getCertificate() throws IoctlCallException;

    /**
     * Initialize the SSL connection
     * @throws IoctlCallException cannot initialize (ie. not in controlled mode, missing configuration etc.)
     */
    void initConnection() throws IoctlCallException;

    /**
     * Reset the Session
     * @throws IoctlCallException cannot reset session (ie. not in controlled mode, missing configuration etc.)
     */
    void resetSession() throws IoctlCallException;

    /**
     * Reset the Cipher
     * @throws IoctlCallException cannot reset cipher (ie. not in controlled mode, missing configuration etc.)
     */
    void resetCipher() throws IoctlCallException;

    /**
     * Stop the SSL connection
     * @throws IoctlCallException cannot stop connection (ie. not in controlled mode, missing configuration etc.)
     */
    void stopConnection() throws IoctlCallException;

}
