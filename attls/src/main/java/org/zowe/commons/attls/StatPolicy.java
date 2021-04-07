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

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Indicates the policy status for the connection at the time of policy lookup - always returned (except in error cases)
 */
@RequiredArgsConstructor
public enum StatPolicy {

        /**
         * AT-TLS function is off
         */
        OFF((byte) 1),
        /**
         * No policy defined for connection
         */
        NO_POLICY((byte) 2),
        /**
         * Policy defined for connection - AT-TLS not enabled
         */
        NOT_ENABLED((byte) 3),
        /**
         * Policy defined for connection - AT-TLS enabled
         */
        ENABLED((byte) 4),
        /**
         * Policy defined for connection - AT-TLS enabled and Application Controlled
         */
        APPLCNTRL((byte) 5)

    ;

    @Getter
    private final byte value;

    public static StatPolicy valueOf(byte value) {
        for (StatPolicy statPolicy : values()) {
            if (statPolicy.value == value) return statPolicy;
        }
        return null;
    }

}
