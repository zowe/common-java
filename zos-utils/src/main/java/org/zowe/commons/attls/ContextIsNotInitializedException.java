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

/**
 * This exception could be thrown when application asks for AT-TLS data, but the context ({@link AttlsContext})
 * has not been initialized yet ({@link org.zowe.commons.attls.InboundAttls#init(int)}). It can be also thrown when
 * context has disposed yet ({@link org.zowe.commons.attls.InboundAttls#dispose()})
 */
public class ContextIsNotInitializedException extends Exception {
}
