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

package org.wso2.carbon.identity.flow.executors.user.verification.constant;

/**
 * Constants for the user verification executor.
 */
public class UserVerificationConstants {

    public static final String USER_VERIFICATION_EXECUTOR = "UserVerificationExecutor";
    public static final String TOKEN = "token";
    public static final String TOKEN_TYPE = "tokenType";
    public static final String USER_VERIFICATION_AUDIENCE = "urn:wso2:identity:flow:user-verification";
    public static final String TOKEN_VALIDITY_PERIOD_METADATA_KEY = "tokenValidityPeriod";
    public static final long DEFAULT_TOKEN_VALIDITY_PERIOD_MINUTES = 5;

    /**
     * Supported token types.
     */
    public static class TokenTypes {

        public static final String ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
    }
}
