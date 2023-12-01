/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */

package org.zowe.commons.usermap;

public class UserMapper {

    public static final String USERMAP_LIBRARY_NAME = "zowe-usermap";

    static {
        if ("z/os".equalsIgnoreCase(System.getProperty("os.name"))) {
            System.loadLibrary(USERMAP_LIBRARY_NAME);
        }
    }
    public native MapperResponse getUserIDForCertificate(byte[] certificate);
    public native MapperResponse getUserIDForDN(String distinguishedName, String registry);
}
