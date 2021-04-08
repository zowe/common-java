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
 * This exception could be thrown from AT-TLS context ({@link org.zowe.commons.attls.AttlsContext}), when ioctl returns
 * value which is not defined in the Enum. It indicated, that library is older the AT-TLS implementation and it is
 * required to upgrade this library
 */
@Value
public class UnknownEnumValueException extends Exception {

    private static final long serialVersionUID = 8662184734113422578L;

    private final Enum<?> enumClazz;
    private final byte value;
    private final byte value2;

}
