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

import lombok.Value;

/**
 * Collect return and errors code from call ioctl. Errors are described
 * at https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.3.0/com.ibm.zos.v2r3.hald001/sioc.htm
 */
@Value
public class IoctlCallException extends Exception {

    private static final long serialVersionUID = 8799435850381286204L;

    private final int rc;
    private final int errorNo;
    private final int errorNo2;

}
