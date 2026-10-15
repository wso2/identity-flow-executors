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

package org.wso2.carbon.identity.flow.executors.user.verification.validator;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;

/**
 * Validates a token sent to the user verification executor.
 */
public interface UserVerificationTokenValidator {

    /**
     * Get the supported token type.
     *
     * @return Token type.
     */
    String getTokenType();

    /**
     * Validate the token and get its user.
     *
     * @param token       Token.
     * @param context     Flow execution context.
     * @param maxTokenAge Max token age in seconds.
     * @return Authenticated user.
     * @throws FlowEngineClientException If the token is invalid.
     * @throws FlowEngineServerException If an error occurs while validating the token.
     */
    AuthenticatedUser validateAndGetUser(String token, FlowExecutionContext context, long maxTokenAge)
            throws FlowEngineClientException, FlowEngineServerException;
}
