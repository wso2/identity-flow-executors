/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.flow.executors.user.verification.util;

import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages;

/**
 * Utilities for the user verification executor.
 */
public final class UserVerificationUtils {

    private UserVerificationUtils() {

    }

    /**
     * Handle the user verification client exceptions.
     *
     * @param error Error message.
     * @param data  The error message data.
     * @return FlowEngineClientException.
     */
    public static FlowEngineClientException handleClientException(ErrorMessages error, Object... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }
        return new FlowEngineClientException(error.getCode(), error.getMessage(), description);
    }
}
