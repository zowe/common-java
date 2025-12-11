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
import static org.zowe.commons.attls.StatPolicy.ENABLED;
import static org.zowe.commons.attls.StatPolicy.OFF;

class StatPolicyTest {

    @Test
    public void testValueOf() {
        assertSame(OFF, StatPolicy.valueOf((byte) 1));
        assertSame(ENABLED, StatPolicy.valueOf((byte) 4));
        assertNull(StatPolicy.valueOf((byte) -1));
    }

}
