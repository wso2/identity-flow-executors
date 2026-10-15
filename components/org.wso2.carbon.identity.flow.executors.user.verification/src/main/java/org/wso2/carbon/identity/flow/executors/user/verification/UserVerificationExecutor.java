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

package org.wso2.carbon.identity.flow.executors.user.verification;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages;
import org.wso2.carbon.identity.flow.executors.user.verification.internal.UserVerificationDataHolder;
import org.wso2.carbon.identity.flow.executors.user.verification.validator.IDTokenValidator;
import org.wso2.carbon.identity.flow.executors.user.verification.validator.UserVerificationTokenValidator;
import org.wso2.carbon.identity.flow.mgt.model.ExecutorDTO;
import org.wso2.carbon.identity.flow.mgt.model.NodeConfig;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountDisableServiceException;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ResidentIdpPropertyName.ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.DEFAULT_MAX_TOKEN_AGE_SECONDS;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.MAX_TOKEN_AGE_METADATA_KEY;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.TOKEN;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.TOKEN_TYPE;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.USER_VERIFICATION_EXECUTOR;

/**
 * Executor that identifies the flow user from the token the app sends when starting the flow.
 */
public class UserVerificationExecutor implements Executor {

    private static final Log LOG = LogFactory.getLog(UserVerificationExecutor.class);

    private final Map<String, UserVerificationTokenValidator> tokenValidators = new HashMap<>();

    public UserVerificationExecutor() {

        this(Collections.singletonList(new IDTokenValidator()));
    }

    UserVerificationExecutor(List<UserVerificationTokenValidator> validators) {

        for (UserVerificationTokenValidator validator : validators) {
            tokenValidators.put(validator.getTokenType(), validator);
        }
    }

    @Override
    public String getName() {

        return USER_VERIFICATION_EXECUTOR;
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) {

        ExecutorResponse response = new ExecutorResponse();
        String token = context.getUserInputData().get(TOKEN);
        String tokenType = context.getUserInputData().get(TOKEN_TYPE);
        List<String> missingInputs = new ArrayList<>();
        if (StringUtils.isBlank(token)) {
            missingInputs.add(TOKEN);
        }
        if (StringUtils.isBlank(tokenType)) {
            missingInputs.add(TOKEN_TYPE);
        }
        if (!missingInputs.isEmpty()) {
            return clientInputRequiredResponse(response, missingInputs.toArray(new String[0]));
        }
        UserVerificationTokenValidator tokenValidator = tokenValidators.get(tokenType);
        if (tokenValidator == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User verification failed: unsupported token type: " + tokenType);
            }
            return userErrorResponse(response, ErrorMessages.ERROR_CODE_UNSUPPORTED_TOKEN_TYPE);
        }

        try {
            String tenantDomain = context.getTenantDomain();
            AuthenticatedUser user = tokenValidator.validateAndGetUser(token, context, getMaxTokenAge(context));
            if (isAccountLocked(user, tenantDomain)) {
                LOG.debug("User verification failed: the user account is locked.");
                return userErrorResponse(response, ErrorMessages.ERROR_CODE_ACCOUNT_LOCKED);
            }
            if (isAccountDisabled(user, tenantDomain)) {
                LOG.debug("User verification failed: the user account is disabled.");
                return userErrorResponse(response, ErrorMessages.ERROR_CODE_ACCOUNT_DISABLED);
            }
            setupFlowUser(context, user, tenantDomain);
            response.setResult(Constants.ExecutorStatus.STATUS_COMPLETE);
            return response;
        } catch (FlowEngineClientException e) {
            return userErrorResponse(response, e.getErrorCode(), e.getMessage(), e.getDescription());
        } catch (FlowEngineServerException | UserStoreException e) {
            String errorMessage = "Error while verifying the token.";
            LOG.error(errorMessage, e);
            return errorResponse(response, errorMessage);
        }
    }

    @Override
    public List<String> getInitiationData() {

        return Arrays.asList(TOKEN, TOKEN_TYPE);
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext context) {

        return null;
    }

    // Enable with the new flow type.
    // @Override
    // public Set<FlowTypes> getSupportedFlowTypes() {
    //
    //     return EnumSet.of(FlowTypes.<NEW_FLOW_TYPE>);
    // }
    //
    // @Override
    // public FlowExecutorMetadata getExecutorMetadata() {
    //
    //     return FlowExecutorMetadata.builder()
    //             .displayName("User Verification")
    //             .icon("assets/images/icons/ticket-check.svg")
    //             .build();
    // }

    /**
     * Check whether the user account is locked.
     */
    private boolean isAccountLocked(AuthenticatedUser user, String tenantDomain) throws FlowEngineServerException {

        try {
            return UserVerificationDataHolder.getInstance().getAccountLockService()
                    .isAccountLocked(user.getUserName(), tenantDomain, user.getUserStoreDomain());
        } catch (AccountLockServiceException e) {
            throw new FlowEngineServerException(null, "Error while checking the account lock status of the user.",
                    null, e);
        }
    }

    /**
     * Check whether the user account is disabled, when account disabling is enabled for the tenant.
     */
    private boolean isAccountDisabled(AuthenticatedUser user, String tenantDomain) throws FlowEngineServerException {

        try {
            if (!isAccountDisablingEnabled(tenantDomain)) {
                return false;
            }
            return UserVerificationDataHolder.getInstance().getAccountDisableService()
                    .isAccountDisabled(user.getUserName(), tenantDomain, user.getUserStoreDomain());
        } catch (IllegalArgumentException | AccountDisableServiceException | FrameworkException e) {
            throw new FlowEngineServerException(null, "Error while checking the account disable status of the user.",
                    null, e);
        }
    }

    private boolean isAccountDisablingEnabled(String tenantDomain) throws FrameworkException {

        Property accountDisableConfigProperty = FrameworkUtils.getResidentIdpConfiguration(
                ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY, tenantDomain);
        return accountDisableConfigProperty != null && Boolean.parseBoolean(accountDisableConfigProperty.getValue());
    }

    /**
     * Set up the flow user with the console profile claims, user ID and username.
     */
    private void setupFlowUser(FlowExecutionContext context, AuthenticatedUser user, String tenantDomain)
            throws UserStoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserStoreManager userStoreManager = UserVerificationDataHolder.getInstance()
                .getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();

        try {
            List<LocalClaim> localClaimList = UserVerificationDataHolder.getInstance()
                    .getClaimMetadataManagementService()
                    .getSupportedLocalClaimsForProfile(tenantDomain,
                            ClaimConstants.DefaultAllowedClaimProfile.CONSOLE.getProfileName());
            String[] claimURIs = localClaimList.stream()
                    .map(LocalClaim::getClaimURI)
                    .toArray(String[]::new);

            String domainQualifiedName = IdentityUtil.addDomainToName(user.getUserName(),
                    user.getUserStoreDomain());
            Map<String, String> claimsMap = userStoreManager.getUserClaimValues(domainQualifiedName, claimURIs,
                    null);

            FlowUser flowUser = context.getFlowUser();
            flowUser.addClaims(claimsMap);
            flowUser.setUserId(user.getUserId());
            flowUser.setUsername(domainQualifiedName);
        } catch (ClaimMetadataException | UserIdNotFoundException e) {
            throw new UserStoreException("Error while retrieving or setting user claims", e);
        }
    }

    /**
     * Get the max token age from the step setting, falling back to the default.
     */
    private long getMaxTokenAge(FlowExecutionContext context) {

        String maxTokenAge = getMetadataValue(context, MAX_TOKEN_AGE_METADATA_KEY);
        if (StringUtils.isNotBlank(maxTokenAge)) {
            try {
                long value = Long.parseLong(maxTokenAge.trim());
                if (value > 0) {
                    return value;
                }
            } catch (NumberFormatException e) {
                // Fall back to the default max token age.
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Invalid max token age: " + maxTokenAge + ". Using the default value: "
                        + DEFAULT_MAX_TOKEN_AGE_SECONDS);
            }
        }
        return DEFAULT_MAX_TOKEN_AGE_SECONDS;
    }

    private String getMetadataValue(FlowExecutionContext context, String key) {

        NodeConfig currentNode = context.getCurrentNode();
        if (currentNode == null) {
            return null;
        }
        ExecutorDTO executorConfig = currentNode.getExecutorConfig();
        if (executorConfig == null) {
            return null;
        }
        Map<String, String> metadata = executorConfig.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        return metadata.get(key);
    }

    private ExecutorResponse errorResponse(ExecutorResponse response, String message) {

        response.setErrorMessage(message);
        response.setResult(Constants.ExecutorStatus.STATUS_ERROR);
        return response;
    }

    private ExecutorResponse clientInputRequiredResponse(ExecutorResponse response, String... fields) {

        response.setResult(Constants.ExecutorStatus.STATUS_CLIENT_INPUT_REQUIRED);
        response.setRequiredData(Arrays.asList(fields));
        return response;
    }

    private ExecutorResponse userErrorResponse(ExecutorResponse response, ErrorMessages error) {

        return userErrorResponse(response, error.getCode(), error.getMessage(), error.getDescription());
    }

    private ExecutorResponse userErrorResponse(ExecutorResponse response, String errorCode, String message,
                                               String description) {

        response.setErrorCode(errorCode);
        response.setErrorMessage(message);
        response.setErrorDescription(description);
        response.setResult(Constants.ExecutorStatus.STATUS_USER_ERROR);
        return response;
    }
}
