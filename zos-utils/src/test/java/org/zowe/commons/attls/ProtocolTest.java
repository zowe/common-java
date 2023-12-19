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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.zowe.commons.attls.Protocol.*;

public class ProtocolTest {

    @Test
    public void testValueOf() {
        assertSame(NON_SECURE, Protocol.valueOf((byte) 0, (byte) 0));
        assertSame(SSL3, Protocol.valueOf((byte) 3, (byte) 0));
        assertSame(TLS1_3, Protocol.valueOf((byte) 3, (byte) 4));
        assertNull(Protocol.valueOf((byte) -1, (byte) 0));
        assertNull(Protocol.valueOf((byte) 0, (byte) -1));
        assertNull(Protocol.valueOf((byte) -1, (byte) -1));
    }

}
