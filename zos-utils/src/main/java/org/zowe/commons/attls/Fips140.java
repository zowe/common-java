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

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Indicates the level of FIPS compliance, if any - returned when connection is secure for connection
 */
@AllArgsConstructor
public enum Fips140 {

        /**
         * FIPS compliance is not set
         */
        FIPS140_OFF((byte) 0),
        /**
         * FIPS 140 On is set
         */
        TTLS_FIPS140_ON((byte) 1),
        /**
         * FIPS 140 Level1 is set
         */
        TTLS_FIPS140_LEVEL1((byte) 2),
        /**
         * FIPS 140 Level2 is set
         */
        TTLS_FIPS140_LEVEL2((byte) 3),
        /**
         * FIPS 140 Level3 is set
         */
        TTLS_FIPS140_LEVEL3((byte) 4)

    ;

    @Getter
    private final byte value;

    public static Fips140 valueOf(byte value) {
        for (Fips140 fips140 : values()) {
            if (fips140.value == value) return fips140;
        }

        return null;
    }

}
