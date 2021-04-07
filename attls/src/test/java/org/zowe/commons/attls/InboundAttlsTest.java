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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class InboundAttlsTest {

    @Mock
    private AttlsContext attlsContext;

    private ThreadLocal<AttlsContext> attlsContexts;

    @BeforeEach
    public void setUp() {
        attlsContexts = (ThreadLocal<AttlsContext>) ReflectionTestUtils.getField(InboundAttls.class, "contexts");
        attlsContexts.set(attlsContext);
    }

    @Test
    public void testInit_whenAlwaysLoadCertificateIsFalse() throws ContextIsNotInitializedException {
        InboundAttls.setAlwaysLoadCertificate(false);
        InboundAttls.init(123);
        assertNotSame(attlsContext, InboundAttls.get());
        assertEquals(123, ReflectionTestUtils.getField(InboundAttls.get(), "id"));
        assertFalse((Boolean) ReflectionTestUtils.getField(InboundAttls.get(), "alwaysLoadCertificate"));
    }

    @Test
    public void testInit_whenAlwaysLoadCertificateIsTrue() throws ContextIsNotInitializedException {
        InboundAttls.setAlwaysLoadCertificate(true);
        InboundAttls.init(852);
        assertNotSame(attlsContext, InboundAttls.get());
        assertEquals(852 , ReflectionTestUtils.getField(InboundAttls.get(), "id"));
        assertTrue((Boolean) ReflectionTestUtils.getField(InboundAttls.get(), "alwaysLoadCertificate"));
    }

    @Test
    public void testDispose() throws ContextIsNotInitializedException {
        assertNotNull(InboundAttls.get());
        InboundAttls.dispose();
        assertThrows(ContextIsNotInitializedException.class, InboundAttls::get);
    }

    private void testCommand(String name) {
        try {
            Method inboundAttlsMethod = InboundAttls.class.getMethod(name);
            Method attlsContextMethod = AttlsContext.class.getMethod(name);

            attlsContextMethod.invoke(verify(attlsContext, never()));
            inboundAttlsMethod.invoke(null);
            attlsContextMethod.invoke(verify(attlsContext, times(1)));

            InboundAttls.dispose();
            try {
                inboundAttlsMethod.invoke(null);
                fail();
            } catch (InvocationTargetException ite) {
                assertTrue(ite.getTargetException() instanceof ContextIsNotInitializedException);
            }
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            fail(e.getMessage());
        }
    }

    private <T> void testGetter(String name, boolean same, T...values) {
        try {
            Method inboundAttlsMethod = InboundAttls.class.getMethod(name);
            Method attlsContextMethod = AttlsContext.class.getMethod(name);

            for (int i = 0; i < values.length; i++) {
                attlsContextMethod.invoke(doReturn(values[i]).when(attlsContext));

                attlsContextMethod.invoke(verify(attlsContext, times(i)));
                T value = (T) inboundAttlsMethod.invoke(null);
                attlsContextMethod.invoke(verify(attlsContext, times(i + 1)));
                if (same) {
                    assertSame(values[i], value);
                } else {
                    assertEquals(values[i], value);
                }
            }

            InboundAttls.dispose();
            try {
                inboundAttlsMethod.invoke(null);
                fail();
            } catch (InvocationTargetException ite) {
                assertTrue(ite.getTargetException() instanceof ContextIsNotInitializedException);
            }
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            fail(e.getMessage());
        }
    }

    private <T> void testEqualsGetter(String name, T...values) {
        testGetter(name, false, values);
    }

    private <T> void testSameGetter(String name, T...values) {
        testGetter(name, true, values);
    }

    @Test
    public void testClean() {
        testCommand("clean");
    }

    @Test
    public void testStatPolicy() {
        testSameGetter("getStatPolicy", StatPolicy.values());
    }

    @Test
    public void testStatConn() {
        testSameGetter("getStatConn", StatConn.values());
    }

    @Test
    public void testProtocol() {
        testSameGetter("getProtocol", Protocol.values());
    }

    @Test
    public void testNegotiatedCipher2() {
        testSameGetter("getNegotiatedCipher2", "XA", "", "SS");
    }

    @Test
    public void testSecurityType() {
        testSameGetter("getSecurityType", SecurityType.values());
    }

    @Test
    public void testGetUserId() {
        testSameGetter("getUserId", "user", "user2");
    }

    @Test
    public void testGetFips140() {
        testSameGetter("getFips140", Fips140.values());
    }

    @Test
    public void testFlags() {
        testEqualsGetter("getFlags", (byte) 1, (byte) 5);
    }

    @Test
    public void testNegotiatedCipher4() {
        testSameGetter("getNegotiatedCipher4", "ABCD", "", "QWER");
    }

    @Test
    public void testNegotiatedKeyShare() {
        testSameGetter("getNegotiatedKeyShare", "shared1", "", "shared2");
    }

    @Test
    public void testCertificate() {
        testSameGetter("getCertificate", new byte[0], new byte[] {1, 5});
    }

    @Test
    public void testResetSession() {
        testCommand("resetSession");
    }

    @Test
    public void testResetCipher() {
        testCommand("resetCipher");
    }

    @AfterEach
    public void tearDown() {
        attlsContexts.remove();
    }

    @FunctionalInterface
    interface VoidMethodWithException<E extends Exception> {

        public void method() throws E;

    }

}
