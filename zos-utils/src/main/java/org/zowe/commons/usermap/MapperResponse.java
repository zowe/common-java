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

public class MapperResponse {
    private String userId;
    private int rc;
    private int safRc;
    private int racfRc;
    private int racfRs;

    public MapperResponse(String userId, int rc, int safRc, int racfRc, int racfRs) {
        this.userId = userId;
        this.rc = rc;
        this.safRc = safRc;
        this.racfRc = racfRc;
        this.racfRs = racfRs;
    }

    public String getUserId() {
        return userId;
    }

    public int getRc() {
        return rc;
    }

    public int getSafRc() {
        return safRc;
    }

    public int getRacfRc() {
        return racfRc;
    }

    public int getRacfRs() {
        return racfRs;
    }

    @Override
    public String toString() {
        return "MapperResponse{" +
                "userId='" + userId + '\'' +
                ", rc=" + rc +
                ", safRc=" + safRc +
                ", racfRc=" + racfRc +
                ", racfRs=" + racfRs +
                '}';
    }
}
