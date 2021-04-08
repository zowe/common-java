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

import lombok.Setter;
import lombok.experimental.UtilityClass;

/**
 * This class collects incoming calls and its AT-TLS context. By thread is possible to get context anywhere or directly
 * call method of AttlsContext.
 */
@UtilityClass
public class InboundAttls {

    /**
     * All initialized AT-TLS context at the moment
     */
    private static ThreadLocal<AttlsContext> contexts = new ThreadLocal<>();

    /**
     * If this value is true, for each incoming session will be fetched certificate together with other AT-TLS
     * information.
     */
    @Setter
    private static boolean alwaysLoadCertificate;

    /**
     * Initialize context for this thread
     * @param id file description of socket
     */
    public static void init(int id) {
        contexts.set(new AttlsContext(id, alwaysLoadCertificate));
    }

    /**
     * Clean context for this thread
     */
    public static void dispose() {
        contexts.remove();
    }

    /**
     * Get AT-TLS context for this thread
     * @return current AttlsContext
     * @throws ContextIsNotInitializedException when no context was initialized
     */
    public static AttlsContext get() throws ContextIsNotInitializedException {
        AttlsContext context = contexts.get();
        if (context == null) throw new ContextIsNotInitializedException();
        return context;
    }

    /**
     * Call {@link AttlsContext#clean()} for incoming call of this thread.
     * @throws ContextIsNotInitializedException when no context was initialized
     */
    public static void clean() throws ContextIsNotInitializedException {
        get().clean();
    }

    /**
     * Call {@link AttlsContext#getStatPolicy()} for incoming call of this thread.
     * @return policy status
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws UnknownEnumValueException StatPolicy does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static StatPolicy getStatPolicy() throws ContextIsNotInitializedException, UnknownEnumValueException, IoctlCallException {
        return get().getStatPolicy();
    }

    public static StatConn getStatConn() throws ContextIsNotInitializedException, UnknownEnumValueException, IoctlCallException {
        return get().getStatConn();
    }

    /**
     * Call {@link AttlsContext#getProtocol()} for incoming call of this thread.
     * @return SSL protocol
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws UnknownEnumValueException StatPolicy does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static Protocol getProtocol() throws ContextIsNotInitializedException, IoctlCallException, UnknownEnumValueException {
        return get().getProtocol();
    }

    /**
     * Call {@link AttlsContext#getNegotiatedCipher2()} for incoming call of this thread.
     * @return negoriated cipher (2 characters)
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static String getNegotiatedCipher2() throws ContextIsNotInitializedException, IoctlCallException {
        return get().getNegotiatedCipher2();
    }

    /**
     * Call {@link AttlsContext#getSecurityType()} for incoming call of this thread.
     * @return security type
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws UnknownEnumValueException StatPolicy does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static SecurityType getSecurityType() throws ContextIsNotInitializedException, IoctlCallException, UnknownEnumValueException {
        return get().getSecurityType();
    }

    /**
     * Call {@link AttlsContext#getUserId()} for incoming call of this thread.
     * @return partner user ID
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static String getUserId() throws ContextIsNotInitializedException, IoctlCallException {
        return get().getUserId();
    }

    /**
     * Call {@link AttlsContext#getFips140()} for incoming call of this thread.
     * @return level of FIPS compliance
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws UnknownEnumValueException StatPolicy does not contain a value (AT-TLS is newer than library)
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static Fips140 getFips140() throws ContextIsNotInitializedException, IoctlCallException, UnknownEnumValueException {
        return get().getFips140();
    }

    /**
     * Call {@link AttlsContext#getFlags()} for incoming call of this thread.
     * @return flags (reserved for IBM use)
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static byte getFlags() throws ContextIsNotInitializedException, IoctlCallException {
        return get().getFlags();
    }

    /**
     * Call {@link AttlsContext#getNegotiatedCipher4()} for incoming call of this thread.
     * @return negotiated cipher (4 characters)
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static String getNegotiatedCipher4() throws ContextIsNotInitializedException, IoctlCallException {
        return get().getNegotiatedCipher4();
    }

    /**
     * Call {@link AttlsContext#getNegotiatedKeyShare()} for incoming call of this thread.
     * @return four character negotiated key share in use for the connection
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static String getNegotiatedKeyShare() throws ContextIsNotInitializedException, IoctlCallException {
        return get().getNegotiatedKeyShare();
    }

    /**
     * Call {@link AttlsContext#getCertificate()} for incoming call of this thread.
     * @return partner certificate
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static byte[] getCertificate() throws ContextIsNotInitializedException, IoctlCallException {
        return get().getCertificate();
    }

    /**
     * Call {@link AttlsContext#resetSession()} for incoming call of this thread.
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static void resetSession() throws ContextIsNotInitializedException, IoctlCallException {
        get().resetSession();
    }

    /**
     * Call {@link AttlsContext#resetCipher()} for incoming call of this thread.
     * @throws ContextIsNotInitializedException when no context was initialized
     * @throws IoctlCallException unexpected error in call of ioctl
     */
    public static void resetCipher() throws ContextIsNotInitializedException, IoctlCallException {
        get().resetCipher();
    }

}
