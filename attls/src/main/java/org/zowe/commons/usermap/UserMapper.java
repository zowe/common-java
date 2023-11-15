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
import java.io.File;
import java.io.FileInputStream;
public class UserMapper {
    public static void main(String[] args) throws Exception {
        System.loadLibrary("zowe-usermap");
        System.out.println(args[0]);
        File file = new File(args[0]);

        FileInputStream fis = new FileInputStream(file);
        byte[]cert = new byte[(int)file.length()];
        fis.read(cert);
        UserMapper mapper = new UserMapper();
        MapperResponse certUser = mapper.getUserIDForCertificate(cert);
        System.out.println("cert user:" + certUser);
        MapperResponse us = mapper.getUserIDForDN(args[1],"broadcom.okta.com");
        System.out.println("distributed user:" +us);
    }
    public native MapperResponse getUserIDForCertificate(byte[] certificate);
    public native MapperResponse getUserIDForDN(String distinguishedName, String registry);
}
