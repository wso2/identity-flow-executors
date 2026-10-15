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
    public static final String MAX_TOKEN_AGE_METADATA_KEY = "maxTokenAge";
    public static final long DEFAULT_MAX_TOKEN_AGE_SECONDS = 300;

    /**
     * Supported token types.
     */
    public static class TokenTypes {

        public static final String ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
    }

    /**
     * Error messages of the user verification executor.
     */
    public enum ErrorMessages {

        ERROR_CODE_ACCOUNT_DISABLED("60201",
                "Account disabled.",
                "The user account is disabled."),
        ERROR_CODE_ACCOUNT_LOCKED("60202",
                "Account locked.",
                "The user account is locked."),
        ERROR_CODE_UNSUPPORTED_TOKEN_TYPE("60203",
                "Unsupported token type.",
                "The token type is not supported."),
        ERROR_CODE_INVALID_TOKEN("60204",
                "Invalid token.",
                "The token is invalid."),
        ERROR_CODE_INVALID_TOKEN_AUDIENCE("60205",
                "Invalid token audience.",
                "Invalid audience values provided."),
        ERROR_CODE_TOKEN_ISSUED_BEFORE_ALLOWED_TIME("60206",
                "Token too old.",
                "The token is issued before the allowed time."),
        ERROR_CODE_TOKEN_EXPIRED("60207",
                "Token expired.",
                "The token is expired."),
        ERROR_CODE_USER_NOT_FOUND("60208",
                "User not found.",
                "The user could not be resolved in the organization: %s.");

        private final String code;
        private final String message;
        private final String description;

        ErrorMessages(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        public String getDescription() {

            return description;
        }
    }
}
