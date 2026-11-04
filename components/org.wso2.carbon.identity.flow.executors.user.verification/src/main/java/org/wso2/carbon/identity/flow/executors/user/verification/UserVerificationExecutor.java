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
import org.wso2.carbon.identity.flow.executors.user.verification.internal.UserVerificationDataHolder;
import org.wso2.carbon.identity.flow.executors.user.verification.validator.IDTokenValidator;
import org.wso2.carbon.identity.flow.executors.user.verification.validator.UserVerificationTokenValidator;
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
import java.util.concurrent.TimeUnit;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ResidentIdpPropertyName.ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ErrorMessages.ERROR_CODE_EXECUTOR_FAILURE;
import static org.wso2.carbon.identity.flow.execution.engine.util.FlowExecutionEngineUtils.handleServerException;
import static org.wso2.carbon.identity.flow.executors.common.util.FlowExecutorUtils.clientInputRequiredResponse;
import static org.wso2.carbon.identity.flow.executors.common.util.FlowExecutorUtils.getMetadataValue;
import static org.wso2.carbon.identity.flow.executors.common.util.FlowExecutorUtils.serverErrorResponse;
import static org.wso2.carbon.identity.flow.executors.common.util.FlowExecutorUtils.userErrorResponse;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.DEFAULT_TOKEN_VALIDITY_PERIOD_MINUTES;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.TOKEN;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.TOKEN_TYPE;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.TOKEN_VALIDITY_PERIOD_METADATA_KEY;
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
            return userErrorResponse(response, "The token type is not supported.");
        }

        try {
            String tenantDomain = context.getTenantDomain();
            AuthenticatedUser user = tokenValidator.validateAndGetUser(token, context, getTokenValidityPeriod(context));
            if (isAccountLocked(user, tenantDomain)) {
                LOG.debug("User verification failed: the user account is locked.");
                return userErrorResponse(response, "The user account is locked.");
            }
            if (isAccountDisabled(user, tenantDomain)) {
                LOG.debug("User verification failed: the user account is disabled.");
                return userErrorResponse(response, "The user account is disabled.");
            }
            setupFlowUser(context, user, tenantDomain);
            response.setResult(Constants.ExecutorStatus.STATUS_COMPLETE);
            return response;
        } catch (FlowEngineClientException e) {
            return userErrorResponse(response, e.getDescription());
        } catch (FlowEngineServerException | UserStoreException e) {
            String errorMessage = "Error while verifying the token.";
            LOG.error(errorMessage, e);
            return serverErrorResponse(response, errorMessage);
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
    //             .description("Verify user identity from a token.")
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
            throw handleServerException(ERROR_CODE_EXECUTOR_FAILURE, e,
                    "Error while checking the account lock status of the user.");
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
            throw handleServerException(ERROR_CODE_EXECUTOR_FAILURE, e,
                    "Error while checking the account disable status of the user.");
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
     * Get the token validity period in seconds from the step setting, falling back to the default.
     */
    private long getTokenValidityPeriod(FlowExecutionContext context) {

        String tokenValidityPeriod = getMetadataValue(context, TOKEN_VALIDITY_PERIOD_METADATA_KEY);
        if (StringUtils.isNotBlank(tokenValidityPeriod)) {
            try {
                long value = Long.parseLong(tokenValidityPeriod.trim());
                if (value > 0) {
                    return TimeUnit.MINUTES.toSeconds(value);
                }
            } catch (NumberFormatException e) {
                // Fall back to the default token validity period.
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Invalid token validity period: " + tokenValidityPeriod + ". Using the default value: "
                        + DEFAULT_TOKEN_VALIDITY_PERIOD_MINUTES);
            }
        }
        return TimeUnit.MINUTES.toSeconds(DEFAULT_TOKEN_VALIDITY_PERIOD_MINUTES);
    }
}
