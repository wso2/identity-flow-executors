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

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.executors.user.verification.internal.UserVerificationDataHolder;
import org.wso2.carbon.identity.flow.executors.user.verification.validator.UserVerificationTokenValidator;
import org.wso2.carbon.identity.flow.mgt.model.ExecutorDTO;
import org.wso2.carbon.identity.flow.mgt.model.NodeConfig;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountDisableService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ResidentIdpPropertyName.ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_CLIENT_INPUT_REQUIRED;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.DEFAULT_MAX_TOKEN_AGE_SECONDS;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages.ERROR_CODE_ACCOUNT_DISABLED;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages.ERROR_CODE_ACCOUNT_LOCKED;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages.ERROR_CODE_INVALID_TOKEN;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_TOKEN_TYPE;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.MAX_TOKEN_AGE_METADATA_KEY;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.TOKEN;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.TOKEN_TYPE;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.TokenTypes.ID_TOKEN_TYPE;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.USER_VERIFICATION_EXECUTOR;

/**
 * Test class for UserVerificationExecutor.
 */
@WithCarbonHome
@WithAxisConfiguration
public class UserVerificationExecutorTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String TOKEN_VALUE = "token-value";
    private static final String USER_ID = "4b4414e1-916b-4475-aaee-6b0751c29ff6";
    private static final String USER_NAME = "john";
    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";

    private UserVerificationTokenValidator tokenValidator;
    private UserVerificationExecutor executor;
    private FlowExecutionContext context;
    private AbstractUserStoreManager userStoreManager;
    private AccountLockService accountLockService;
    private AccountDisableService accountDisableService;

    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<FrameworkUtils> frameworkUtils;

    @BeforeMethod
    public void setUp() throws Exception {

        tokenValidator = mock(UserVerificationTokenValidator.class);
        when(tokenValidator.getTokenType()).thenReturn(ID_TOKEN_TYPE);
        executor = new UserVerificationExecutor(Collections.singletonList(tokenValidator));
        context = new FlowExecutionContext();
        context.setTenantDomain(TENANT_DOMAIN);
        when(tokenValidator.validateAndGetUser(anyString(), any(FlowExecutionContext.class), anyLong()))
                .thenReturn(buildUser());

        userStoreManager = mock(AbstractUserStoreManager.class);
        Map<String, String> claims = new HashMap<>();
        claims.put(EMAIL_CLAIM, "john@wso2.com");
        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), any())).thenReturn(claims);
        UserRealm userRealm = mock(UserRealm.class);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        RealmService realmService = mock(RealmService.class);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);

        LocalClaim localClaim = new LocalClaim(EMAIL_CLAIM);
        ClaimMetadataManagementService claimMetadataService = mock(ClaimMetadataManagementService.class);
        when(claimMetadataService.getSupportedLocalClaimsForProfile(anyString(), anyString()))
                .thenReturn(Collections.singletonList(localClaim));

        UserVerificationDataHolder.getInstance().setRealmService(realmService);
        UserVerificationDataHolder.getInstance().setClaimMetadataManagementService(claimMetadataService);

        accountLockService = mock(AccountLockService.class);
        accountDisableService = mock(AccountDisableService.class);
        UserVerificationDataHolder.getInstance().setAccountLockService(accountLockService);
        UserVerificationDataHolder.getInstance().setAccountDisableService(accountDisableService);

        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
        frameworkUtils = mockStatic(FrameworkUtils.class);
    }

    @AfterMethod
    public void tearDown() {

        UserVerificationDataHolder.getInstance().setRealmService(null);
        UserVerificationDataHolder.getInstance().setClaimMetadataManagementService(null);
        UserVerificationDataHolder.getInstance().setAccountLockService(null);
        UserVerificationDataHolder.getInstance().setAccountDisableService(null);
        identityTenantUtil.close();
        frameworkUtils.close();
    }

    @Test
    public void testWithoutInputs() {

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), STATUS_CLIENT_INPUT_REQUIRED);
        assertEquals(response.getRequiredData(), Arrays.asList(TOKEN, TOKEN_TYPE));
        assertEquals(executor.getInitiationData(), Arrays.asList(TOKEN, TOKEN_TYPE));
    }

    @Test
    public void testWithoutTokenType() {

        context.addUserInputData(TOKEN, TOKEN_VALUE);

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), STATUS_CLIENT_INPUT_REQUIRED);
        assertEquals(response.getRequiredData(), Collections.singletonList(TOKEN_TYPE));
    }

    @Test
    public void testWithoutToken() {

        context.addUserInputData(TOKEN_TYPE, ID_TOKEN_TYPE);

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), STATUS_CLIENT_INPUT_REQUIRED);
        assertEquals(response.getRequiredData(), Collections.singletonList(TOKEN));
    }

    @Test
    public void testUnsupportedTokenType() throws Exception {

        context.addUserInputData(TOKEN, TOKEN_VALUE);
        context.addUserInputData(TOKEN_TYPE, "urn:ietf:params:oauth:token-type:access_token");

        assertUserError(ERROR_CODE_UNSUPPORTED_TOKEN_TYPE.getCode(), ERROR_CODE_UNSUPPORTED_TOKEN_TYPE.getMessage(),
                ERROR_CODE_UNSUPPORTED_TOKEN_TYPE.getDescription());
        verify(tokenValidator, never()).validateAndGetUser(anyString(), any(FlowExecutionContext.class), anyLong());
    }

    @Test
    public void testValidToken() throws Exception {

        addInputs();

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), STATUS_COMPLETE);
        assertEquals(context.getFlowUser().getUserId(), USER_ID);
        assertEquals(context.getFlowUser().getUsername(), USER_NAME);
        assertEquals(context.getFlowUser().getClaim(EMAIL_CLAIM), "john@wso2.com");
        assertNull(context.getProperty(TOKEN));
        verify(tokenValidator).validateAndGetUser(TOKEN_VALUE, context, DEFAULT_MAX_TOKEN_AGE_SECONDS);
    }

    @Test
    public void testInvalidToken() throws Exception {

        when(tokenValidator.validateAndGetUser(anyString(), any(FlowExecutionContext.class), anyLong()))
                .thenThrow(new FlowEngineClientException(ERROR_CODE_INVALID_TOKEN.getCode(),
                        ERROR_CODE_INVALID_TOKEN.getMessage(), ERROR_CODE_INVALID_TOKEN.getDescription()));
        addInputs();

        assertUserError(ERROR_CODE_INVALID_TOKEN.getCode(), ERROR_CODE_INVALID_TOKEN.getMessage(),
                ERROR_CODE_INVALID_TOKEN.getDescription());
    }

    @Test
    public void testTokenValidationServerError() throws Exception {

        when(tokenValidator.validateAndGetUser(anyString(), any(FlowExecutionContext.class), anyLong()))
                .thenThrow(new FlowEngineServerException("Error."));
        addInputs();

        assertEquals(executor.execute(context).getResult(), STATUS_ERROR);
    }

    @Test
    public void testLockedAccount() throws Exception {

        when(accountLockService.isAccountLocked(USER_NAME, TENANT_DOMAIN, USER_STORE_DOMAIN)).thenReturn(true);
        addInputs();

        assertUserError(ERROR_CODE_ACCOUNT_LOCKED.getCode(), ERROR_CODE_ACCOUNT_LOCKED.getMessage(),
                ERROR_CODE_ACCOUNT_LOCKED.getDescription());
        assertNull(context.getFlowUser().getUserId());
    }

    @Test
    public void testDisabledAccount() throws Exception {

        mockAccountDisablingEnabled("true");
        when(accountDisableService.isAccountDisabled(USER_NAME, TENANT_DOMAIN, USER_STORE_DOMAIN)).thenReturn(true);
        addInputs();

        assertUserError(ERROR_CODE_ACCOUNT_DISABLED.getCode(), ERROR_CODE_ACCOUNT_DISABLED.getMessage(),
                ERROR_CODE_ACCOUNT_DISABLED.getDescription());
        assertNull(context.getFlowUser().getUserId());
    }

    @Test
    public void testDisabledAccountWhenAccountDisablingIsNotEnabled() throws Exception {

        mockAccountDisablingEnabled("false");
        when(accountDisableService.isAccountDisabled(USER_NAME, TENANT_DOMAIN, USER_STORE_DOMAIN)).thenReturn(true);
        addInputs();

        assertEquals(executor.execute(context).getResult(), STATUS_COMPLETE);
        verify(accountDisableService, never()).isAccountDisabled(anyString(), anyString(), anyString());
    }

    @Test
    public void testAccountLockServiceError() throws Exception {

        when(accountLockService.isAccountLocked(USER_NAME, TENANT_DOMAIN, USER_STORE_DOMAIN))
                .thenThrow(new AccountLockServiceException("Error."));
        addInputs();

        assertEquals(executor.execute(context).getResult(), STATUS_ERROR);
    }

    @Test
    public void testUserStoreError() throws Exception {

        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), any()))
                .thenThrow(new UserStoreException("Error."));
        addInputs();

        assertEquals(executor.execute(context).getResult(), STATUS_ERROR);
    }

    @Test
    public void testMaxTokenAgeFromStepSetting() throws Exception {

        context.setCurrentNode(buildNode("1200"));
        addInputs();

        assertEquals(executor.execute(context).getResult(), STATUS_COMPLETE);
        verify(tokenValidator).validateAndGetUser(TOKEN_VALUE, context, 1200L);
    }

    @Test
    public void testInvalidMaxTokenAgeFallsBackToDefault() throws Exception {

        context.setCurrentNode(buildNode("invalid"));
        addInputs();

        assertEquals(executor.execute(context).getResult(), STATUS_COMPLETE);
        verify(tokenValidator).validateAndGetUser(TOKEN_VALUE, context, DEFAULT_MAX_TOKEN_AGE_SECONDS);
    }

    private void addInputs() {

        context.addUserInputData(TOKEN, TOKEN_VALUE);
        context.addUserInputData(TOKEN_TYPE, ID_TOKEN_TYPE);
    }

    private void mockAccountDisablingEnabled(String value) {

        Property property = new Property();
        property.setName(ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY);
        property.setValue(value);
        frameworkUtils.when(() -> FrameworkUtils.getResidentIdpConfiguration(ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY,
                TENANT_DOMAIN)).thenReturn(property);
    }

    private void assertUserError(String errorCode, String errorMessage, String errorDescription) {

        ExecutorResponse response = executor.execute(context);
        assertEquals(response.getResult(), STATUS_USER_ERROR);
        assertEquals(response.getErrorCode(), errorCode);
        assertEquals(response.getErrorMessage(), errorMessage);
        assertEquals(response.getErrorDescription(), errorDescription);
    }

    private NodeConfig buildNode(String maxTokenAge) {

        ExecutorDTO executorDTO = new ExecutorDTO(USER_VERIFICATION_EXECUTOR);
        executorDTO.addMetadata(MAX_TOKEN_AGE_METADATA_KEY, maxTokenAge);
        return new NodeConfig.Builder().id("userVerification").executorConfig(executorDTO).build();
    }

    private AuthenticatedUser buildUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserId(USER_ID);
        user.setUserName(USER_NAME);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(TENANT_DOMAIN);
        return user;
    }
}
