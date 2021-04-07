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
 * Indicates the security status for the connection - always returned (except in error cases)
 */
@AllArgsConstructor
public enum StatConn {

        /**
         * Connection is not secure
         */
        NOTSECURE((byte) 1),
        /**
         * Connection handshake in progress
         */
        HS_INPROGRESS((byte) 2),
        /**
         * Connection is secure
         */
        SECURE((byte) 3)

    ;

    @Getter
    private final byte value;

    public static StatConn valueOf(byte value) {
        for (StatConn statConn : values()) {
            if (statConn.value == value) return statConn;
        }
        return null;
    }

}
