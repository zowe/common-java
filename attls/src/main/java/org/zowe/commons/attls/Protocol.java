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
 * Indicates the SSL protocol in use for the connection - returned when connection is secure
 */
@AllArgsConstructor
public enum Protocol {

        /**
         * connection is not secure
         */
        NON_SECURE((byte) 0, (byte) 0),

        /**
         * SSL Version 2
         */
        SSL2((byte) 2, (byte) 0),
        /**
         * SSL Version 3
         */
        SSL3((byte) 3, (byte) 0),
        /**
         * TLS Version 1
         */
        TLS1((byte) 3, (byte) 1),
        /**
         * TLS Version 1.1
         */
        TLS1_1((byte) 3, (byte) 2),
        /**
         * TLS Version 1.2
         */
        TLS1_2((byte) 3, (byte) 3),
        /**
         * TLS Version 1.3
         */
        TLS1_3((byte) 3, (byte) 4)

    ;

    @Getter
    private final byte version;
    @Getter
    private final byte mod;

    public static Protocol valueOf(byte version, byte mod) {
        for (Protocol protocol : values()) {
            if ((protocol.mod == mod) && (protocol.version == version)) return protocol;
        }

        return null;
    }

}
