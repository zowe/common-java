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

public class CertificateResponse {
    private String userId;

    private int rc;
    private int errno;
    private int errno2;

    public CertificateResponse(String userId, int rc, int errno, int errno2) {
        this.userId = userId;
        this.rc = rc;
        this.errno = errno;
        this.errno2 = errno2;
    }

    public String getUserId() {
        return userId;
    }

    public int getErrno2() {
        return errno2;
    }

    public int getRc() {
        return rc;
    }

    public int getErrno() {
        return errno;
    }

    @Override
    public String toString() {
        return "CertificateResponse{" +
                "userId='" + userId + '\'' +
                ", rc=" + rc +
                ", errno=" + errno +
                ", errno2=" + errno2 +
                '}';
    }
}
