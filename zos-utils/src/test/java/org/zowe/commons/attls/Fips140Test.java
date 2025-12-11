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
import static org.zowe.commons.attls.Fips140.FIPS140_OFF;
import static org.zowe.commons.attls.Fips140.TTLS_FIPS140_LEVEL1;

public class Fips140Test {

    @Test
    public void testValueOf() {
        assertSame(FIPS140_OFF, Fips140.valueOf((byte) 0));
        assertSame(TTLS_FIPS140_LEVEL1, Fips140.valueOf((byte) 2));

        assertNull(Fips140.valueOf((byte) -1));
    }

}
