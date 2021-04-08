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
 * Indicates the security type for the connection - returned when policy defined for connection
 */
@RequiredArgsConstructor
public enum SecurityType {

        /**
         * Unknown, ie. AT-TLS is not enabled
         */
        UNKNOWN((byte) 0),

        /**
         * Client
         */
        TTLS_SEC_CLIENT((byte) 1),
        /**
         * Server
         */
        TTLS_SEC_SERVER((byte) 2),
        /**
         * Server with client authentication, ClientAuthType = PassThru
         */
        TTLS_SEC_SRV_CA_PASS((byte) 3),
        /**
         * Server with client authentication, ClientAuthType = Full
         */
        TTLS_SEC_SRV_CA_FULL((byte) 4),
        /**
         * Server with client authentication, ClientAuthType = Required
         */
        TTLS_SEC_SRV_CA_REQD((byte) 5),
        /**
         * Server with client authentication, ClientAuthType = SAFCheck
         */
        TTLS_SEC_SRV_CA_SAFCHK((byte) 6)

    ;

    @Getter
    private final byte value;

    public static SecurityType valueOf(byte value) {
        for (SecurityType securityType : values()) {
            if (securityType.value == value) return securityType;
        }

        return null;
    }

}
