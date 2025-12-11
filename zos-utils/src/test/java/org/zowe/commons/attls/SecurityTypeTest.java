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
import static org.zowe.commons.attls.SecurityType.TTLS_SEC_SRV_CA_FULL;
import static org.zowe.commons.attls.SecurityType.UNKNOWN;

public class SecurityTypeTest {

    @Test
    public void testValueOf() {
        assertSame(UNKNOWN, SecurityType.valueOf((byte) 0));
        assertSame(TTLS_SEC_SRV_CA_FULL, SecurityType.valueOf((byte) 4));
        assertNull(SecurityType.valueOf((byte) -1));
    }

}
