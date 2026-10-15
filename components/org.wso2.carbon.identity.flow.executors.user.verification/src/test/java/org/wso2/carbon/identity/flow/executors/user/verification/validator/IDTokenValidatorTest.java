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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages;
import org.wso2.carbon.identity.flow.executors.user.verification.internal.UserVerificationDataHolder;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.config.models.IssuerDetails;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.expectThrows;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.TENANT_NAME_FROM_CONTEXT;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.DEFAULT_MAX_TOKEN_AGE_SECONDS;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages.ERROR_CODE_INVALID_TOKEN;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages.ERROR_CODE_INVALID_TOKEN_AUDIENCE;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages.ERROR_CODE_TOKEN_EXPIRED;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages.ERROR_CODE_TOKEN_ISSUED_BEFORE_ALLOWED_TIME;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.ErrorMessages.ERROR_CODE_USER_NOT_FOUND;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.TokenTypes.ID_TOKEN_TYPE;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.USER_VERIFICATION_AUDIENCE;

/**
 * Test class for IDTokenValidator.
 */
@WithCarbonHome
@WithAxisConfiguration
public class IDTokenValidatorTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String CLIENT_ID = "test-client-id";
    private static final String ISSUER = "https://localhost:9443/oauth2/token";
    private static final String SUBJECT = "john";
    private static final String USER_ID = "4b4414e1-916b-4475-aaee-6b0751c29ff6";
    private static final String USER_NAME = "john";
    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String ORG_ID = "c2a4d8e6-1f3b-4a5c-9d7e-0b1a2c3d4e5f";
    private static final String ORG_TENANT_DOMAIN = ORG_ID;
    private static final String ROOT_ORG_ID = "10084a8d-113f-4211-a0d5-efe36b082211";
    private static final String ORG_ISSUER = "https://localhost:9443/t/carbon.super/o/" + ORG_ID + "/oauth2/token";
    private static final String REQUEST_CONTEXT_USERNAME = "request-context";
    private static final String MTLS_ISSUER = "https://mtls.localhost:9443/oauth2/token";
    private static final String MUTUAL_TLS_ALIASES_ENABLED = "OAuth.MutualTLSAliases.Enabled";

    private KeyPair keyPair;
    private KeyPair otherKeyPair;
    private IDTokenValidator validator;
    private FlowExecutionContext context;
    private OAuthAppDO oAuthAppDO;
    private String issuerResidentOrganizationId;
    private String issuerContextUsername;

    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<OAuthServerConfiguration> serverConfiguration;

    @BeforeClass
    public void setUpClass() throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        otherKeyPair = generator.generateKeyPair();
    }

    @BeforeMethod
    public void setUp() throws Exception {

        validator = new IDTokenValidator();
        issuerResidentOrganizationId = null;
        issuerContextUsername = null;
        context = new FlowExecutionContext();
        context.setTenantDomain(TENANT_DOMAIN);

        oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setSubjectType(OAuthConstants.SubjectType.PUBLIC.getValue());

        // OAuth2Util reads the server configuration when it is initialized, so mock it first.
        OAuthServerConfiguration configuration = mock(OAuthServerConfiguration.class);
        when(configuration.getTimeStampSkewInSeconds()).thenReturn(60L);
        serverConfiguration = mockStatic(OAuthServerConfiguration.class);
        serverConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(configuration);

        Certificate certificate = buildCertificate(keyPair);
        oAuth2Util = mockStatic(OAuth2Util.class);
        oAuth2Util.when(() -> OAuth2Util.getCertificate(TENANT_DOMAIN)).thenReturn(certificate);
        oAuth2Util.when(() -> OAuth2Util.getAppInformationFromOrgHierarchy(CLIENT_ID, ROOT_ORG_ID))
                .thenReturn(oAuthAppDO);
        oAuth2Util.when(() -> OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)).thenReturn(TENANT_DOMAIN);
        oAuth2Util.when(() -> OAuth2Util.getIdTokenIssuer(TENANT_DOMAIN, CLIENT_ID, false))
                .thenAnswer(invocation -> resolveIdTokenIssuer(false));
        oAuth2Util.when(() -> OAuth2Util.getIdTokenIssuer(TENANT_DOMAIN, CLIENT_ID, true))
                .thenAnswer(invocation -> resolveIdTokenIssuer(true));

        OrganizationManager organizationManager = mock(OrganizationManager.class);
        when(organizationManager.resolveOrganizationId(TENANT_DOMAIN)).thenReturn(ROOT_ORG_ID);
        when(organizationManager.resolveOrganizationId(ORG_TENANT_DOMAIN)).thenReturn(ORG_ID);
        when(organizationManager.getPrimaryOrganizationId(anyString())).thenReturn(ROOT_ORG_ID);
        when(organizationManager.resolveTenantDomain(ROOT_ORG_ID)).thenReturn(TENANT_DOMAIN);
        UserVerificationDataHolder.getInstance().setOrganizationManager(organizationManager);
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(SUBJECT, TENANT_DOMAIN,
                CLIENT_ID)).thenReturn(buildUser());
    }

    @AfterMethod
    public void tearDown() {

        UserVerificationDataHolder.getInstance().setOrganizationManager(null);
        oAuth2Util.close();
        serverConfiguration.close();
    }

    @Test
    public void testTokenType() {

        assertEquals(validator.getTokenType(), ID_TOKEN_TYPE);
    }

    @Test
    public void testValidIdToken() throws Exception {

        AuthenticatedUser user = validate(buildToken(builder -> { }));

        assertEquals(user.getUserId(), USER_ID);
        assertEquals(user.getUserName(), USER_NAME);
    }

    @Test
    public void testSubjectResolvedAsUserId() throws Exception {

        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(USER_ID, TENANT_DOMAIN,
                CLIENT_ID)).thenThrow(new IdentityOAuth2Exception("User not found."));
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUser(USER_ID, TENANT_DOMAIN, CLIENT_ID))
                .thenReturn(buildUser());

        AuthenticatedUser user = validate(buildToken(builder -> builder.subject(USER_ID)));

        assertEquals(user.getUserId(), USER_ID);
        assertEquals(user.getUserName(), USER_NAME);
        assertEquals(user.getUserStoreDomain(), USER_STORE_DOMAIN);
    }

    @Test
    public void testInvalidSignature() throws Exception {

        assertClientError(buildToken(builder -> { }, otherKeyPair));
    }

    @Test
    public void testMalformedToken() {

        assertClientError("not-a-jwt");
    }

    @DataProvider(name = "invalidClaimsData")
    public Object[][] invalidClaimsData() {

        long now = System.currentTimeMillis();
        return new Object[][]{
                {(Consumer<JWTClaimsSet.Builder>) builder -> builder.issuer("https://evil.com/oauth2/token")},
                {(Consumer<JWTClaimsSet.Builder>) builder -> builder.expirationTime(null)},
                {(Consumer<JWTClaimsSet.Builder>) builder -> builder.issueTime(null)},
                {(Consumer<JWTClaimsSet.Builder>) builder -> builder.notBeforeTime(new Date(now + 600_000))},
                {(Consumer<JWTClaimsSet.Builder>) builder -> builder.claim(OAuthConstants.OIDCClaims.AZP, "other")},
                {(Consumer<JWTClaimsSet.Builder>) builder -> builder.claim(OAuthConstants.OIDCClaims.AZP, null)},
                {(Consumer<JWTClaimsSet.Builder>) builder -> builder.audience("other-client-id")}
        };
    }

    @Test(dataProvider = "invalidClaimsData")
    public void testInvalidClaims(Consumer<JWTClaimsSet.Builder> customizer) throws Exception {

        assertClientError(buildToken(customizer));
    }

    @Test
    public void testTokenExpired() throws Exception {

        assertClientError(buildToken(builder -> builder.expirationTime(
                new Date(System.currentTimeMillis() - 600_000))), ERROR_CODE_TOKEN_EXPIRED);
    }

    @Test
    public void testTokenIssuedBeforeAllowedTime() throws Exception {

        assertClientError(buildToken(builder -> builder.issueTime(new Date(System.currentTimeMillis() - 600_000))),
                ERROR_CODE_TOKEN_ISSUED_BEFORE_ALLOWED_TIME);
    }

    @Test
    public void testAudienceWithoutUserVerificationAudience() throws Exception {

        assertClientError(buildToken(builder -> builder.audience(Arrays.asList(CLIENT_ID, ISSUER))),
                ERROR_CODE_INVALID_TOKEN_AUDIENCE);
    }

    @Test
    public void testIssueTimeWithinMaxTokenAge() throws Exception {

        String token = buildToken(builder -> builder.issueTime(new Date(System.currentTimeMillis() - 600_000)));

        assertEquals(validator.validateAndGetUser(token, context, 1200).getUserId(), USER_ID);
    }

    @Test
    public void testApplicationNotInTenant() throws Exception {

        oAuth2Util.when(() -> OAuth2Util.getAppInformationFromOrgHierarchy(CLIENT_ID, ROOT_ORG_ID))
                .thenThrow(new InvalidOAuthClientException("Application not found."));

        assertClientError(buildToken(builder -> { }));
    }

    @Test
    public void testOrganizationWithSharedApplication() throws Exception {

        setUpOrganization();

        assertEquals(validate(buildToken(builder -> { })).getUserId(), USER_ID);
        assertNull(issuerResidentOrganizationId);
        oAuth2Util.verify(() -> OAuth2Util.getCertificate(TENANT_DOMAIN));
        oAuth2Util.verify(() -> OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(SUBJECT, TENANT_DOMAIN,
                ORG_ID, ORG_ID, CLIENT_ID));
    }

    @Test
    public void testRootApplicationInRootContextNotSwitched() throws Exception {

        startRequestContext(null);
        try {
            assertEquals(validate(buildToken(builder -> { })).getUserId(), USER_ID);
            assertEquals(issuerContextUsername, REQUEST_CONTEXT_USERNAME);
        } finally {
            endRequestContext();
        }
    }

    @Test
    public void testOrganizationApplicationInOrganizationContextNotSwitched() throws Exception {

        setUpOrganization();
        setUpOrganizationApplication();
        startRequestContext(ORG_ID);
        try {
            assertEquals(validate(buildToken(builder -> { })).getUserId(), USER_ID);
            assertEquals(issuerContextUsername, REQUEST_CONTEXT_USERNAME);
            assertEquals(issuerResidentOrganizationId, ORG_ID);
            oAuth2Util.verify(() -> OAuth2Util.getCertificate(TENANT_DOMAIN));
            oAuth2Util.verify(() -> OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(SUBJECT, ORG_TENANT_DOMAIN,
                    ORG_ID, ORG_ID, CLIENT_ID));
        } finally {
            endRequestContext();
        }
    }

    @Test
    public void testSharedApplicationInOrganizationContextSwitchedToRoot() throws Exception {

        setUpOrganization();
        startRequestContext(ORG_ID);
        try {
            assertEquals(validate(buildToken(builder -> { })).getUserId(), USER_ID);
            assertNull(issuerContextUsername);
            assertNull(issuerResidentOrganizationId);
            assertEquals(PrivilegedCarbonContext.getThreadLocalCarbonContext().getApplicationResidentOrganizationId(),
                    ORG_ID);
        } finally {
            endRequestContext();
        }
    }

    @Test
    public void testIssuerContextRestored() throws Exception {

        setUpOrganization();
        IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, ORG_TENANT_DOMAIN);

        try {
            assertEquals(validate(buildToken(builder -> { })).getUserId(), USER_ID);
            assertEquals(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT), ORG_TENANT_DOMAIN);
            assertNull(PrivilegedCarbonContext.getThreadLocalCarbonContext().getApplicationResidentOrganizationId());
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(TENANT_NAME_FROM_CONTEXT);
        }
    }

    @Test
    public void testMutualTLSIssuer() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(MUTUAL_TLS_ALIASES_ENABLED)).thenReturn("true");

            assertEquals(validate(buildToken(builder -> builder.issuer(MTLS_ISSUER))).getUserId(), USER_ID);
        }
    }

    @Test
    public void testMutualTLSIssuerWhenAliasesDisabled() throws Exception {

        assertClientError(buildToken(builder -> builder.issuer(MTLS_ISSUER)));
    }

    @Test
    public void testMutualTLSIssuerForOrganizationApplication() throws Exception {

        setUpOrganization();
        setUpOrganizationApplication();
        startRequestContext(ORG_ID);
        try {
            assertClientError(buildToken(builder -> builder.issuer(MTLS_ISSUER)));
        } finally {
            endRequestContext();
        }
    }

    @Test
    public void testOrganizationWithOrganizationIssuer() throws Exception {

        setUpOrganization();
        setUpOrganizationIssuer(keyPair);
        startRequestContext(ORG_ID);
        try {
            assertEquals(validate(buildToken(builder -> builder.issuer(ORG_ISSUER))).getUserId(), USER_ID);
        } finally {
            endRequestContext();
        }
    }

    @Test
    public void testOrganizationIssuerWithTokenSignedByRoot() throws Exception {

        setUpOrganization();
        setUpOrganizationIssuer(otherKeyPair);
        startRequestContext(ORG_ID);
        try {
            assertClientError(buildToken(builder -> builder.issuer(ORG_ISSUER)));
        } finally {
            endRequestContext();
        }
    }

    @Test
    public void testOrganizationIssuerWithRootIssuer() throws Exception {

        setUpOrganization();
        setUpOrganizationIssuer(keyPair);
        startRequestContext(ORG_ID);
        try {
            assertClientError(buildToken(builder -> { }));
        } finally {
            endRequestContext();
        }
    }

    @Test
    public void testApplicationNotInOrganization() throws Exception {

        setUpOrganization();
        oAuth2Util.when(() -> OAuth2Util.getAppInformationFromOrgHierarchy(CLIENT_ID, ORG_ID))
                .thenThrow(new InvalidOAuthClientException("Application not found."));

        assertClientError(buildToken(builder -> { }));
    }

    @Test
    public void testOrganizationSubjectResolvedAsUserId() throws Exception {

        setUpOrganization();
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(USER_ID, TENANT_DOMAIN,
                ORG_ID, ORG_ID, CLIENT_ID)).thenThrow(new IdentityOAuth2Exception("User not found."));
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUser(USER_ID, TENANT_DOMAIN, ORG_ID, ORG_ID, CLIENT_ID))
                .thenReturn(buildOrganizationUser(ORG_ID));

        assertEquals(validate(buildToken(builder -> builder.subject(USER_ID))).getUserId(), USER_ID);
    }

    @Test
    public void testUserNotInOrganization() throws Exception {

        setUpOrganization();
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(SUBJECT, TENANT_DOMAIN,
                ORG_ID, ORG_ID, CLIENT_ID)).thenThrow(new IdentityOAuth2Exception("User not found."));
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUser(SUBJECT, TENANT_DOMAIN, ORG_ID, ORG_ID, CLIENT_ID))
                .thenThrow(new IdentityOAuth2Exception("User not found."));

        assertClientError(buildToken(builder -> { }), ERROR_CODE_USER_NOT_FOUND,
                String.format(ERROR_CODE_USER_NOT_FOUND.getDescription(), ORG_TENANT_DOMAIN));
    }

    @DataProvider(name = "sharedUserData")
    public Object[][] sharedUserData() {

        return new Object[][]{
                {null},
                {"8f3e2b1a-6c5d-4e7f-9a0b-1c2d3e4f5a6b"}
        };
    }

    @Test(dataProvider = "sharedUserData")
    public void testSharedUserInOrganization(String userResidentOrganizationId) throws Exception {

        setUpOrganization();
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(SUBJECT, TENANT_DOMAIN,
                ORG_ID, ORG_ID, CLIENT_ID)).thenReturn(buildOrganizationUser(userResidentOrganizationId));

        assertClientError(buildToken(builder -> { }), ERROR_CODE_USER_NOT_FOUND,
                String.format(ERROR_CODE_USER_NOT_FOUND.getDescription(), ORG_TENANT_DOMAIN));
    }

    @Test
    public void testUserNotFound() throws Exception {

        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(SUBJECT, TENANT_DOMAIN,
                CLIENT_ID)).thenThrow(new IdentityOAuth2Exception("User not found."));
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUser(SUBJECT, TENANT_DOMAIN, CLIENT_ID))
                .thenThrow(new IdentityOAuth2Exception("User not found."));

        assertClientError(buildToken(builder -> { }), ERROR_CODE_USER_NOT_FOUND,
                String.format(ERROR_CODE_USER_NOT_FOUND.getDescription(), TENANT_DOMAIN));
    }

    @Test
    public void testOrganizationResolutionError() throws Exception {

        when(UserVerificationDataHolder.getInstance().getOrganizationManager().resolveOrganizationId(TENANT_DOMAIN))
                .thenThrow(new OrganizationManagementException("Error."));
        String token = buildToken(builder -> { });

        assertThrows(FlowEngineServerException.class,
                () -> validator.validateAndGetUser(token, context, DEFAULT_MAX_TOKEN_AGE_SECONDS));
    }

    /**
     * Set up a flow executed in an organization, with an application shared from the root organization, which owns
     * it. Its ID tokens are issued and signed by the root tenant, unless an issuer organization is set on it.
     */
    private void setUpOrganization() {

        AuthenticatedUser user = buildOrganizationUser(ORG_ID);
        context.setTenantDomain(ORG_TENANT_DOMAIN);
        oAuth2Util.when(() -> OAuth2Util.getAppInformationFromOrgHierarchy(CLIENT_ID, ORG_ID))
                .thenReturn(oAuthAppDO);
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(SUBJECT, TENANT_DOMAIN,
                ORG_ID, ORG_ID, CLIENT_ID)).thenReturn(user);
    }

    /**
     * Make the application the organization's own application instead of one shared from the root organization.
     */
    private void setUpOrganizationApplication() {

        AuthenticatedUser user = buildOrganizationUser(ORG_ID);
        oAuth2Util.when(() -> OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)).thenReturn(ORG_TENANT_DOMAIN);
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(SUBJECT, ORG_TENANT_DOMAIN,
                ORG_ID, ORG_ID, CLIENT_ID)).thenReturn(user);
    }

    /**
     * Set the organization as the token issuer of the organization's own application, with its certificate built
     * from the given key pair.
     */
    private void setUpOrganizationIssuer(KeyPair certificateKeyPair) {

        setUpOrganizationApplication();

        IssuerDetails issuerDetails = new IssuerDetails();
        issuerDetails.setIssuerOrgId(ORG_ID);
        issuerDetails.setIssuerTenantDomain(ORG_TENANT_DOMAIN);
        issuerDetails.setIssuer(ORG_ISSUER);
        oAuthAppDO.setIssuerDetails(issuerDetails);
        Certificate certificate = buildCertificate(certificateKeyPair);
        oAuth2Util.when(() -> OAuth2Util.getCertificate(ORG_TENANT_DOMAIN)).thenReturn(certificate);
    }

    /**
     * Start a carbon context as the request sets up, for the root tenant or the /t/<root>/o/ path of an organization.
     */
    private void startRequestContext(String appResidentOrganizationId) {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantDomain(TENANT_DOMAIN);
        carbonContext.setUsername(REQUEST_CONTEXT_USERNAME);
        carbonContext.setApplicationResidentOrganizationId(appResidentOrganizationId);
        IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, TENANT_DOMAIN);
    }

    private void endRequestContext() {

        IdentityUtil.threadLocalProperties.get().remove(TENANT_NAME_FROM_CONTEXT);
        PrivilegedCarbonContext.endTenantFlow();
    }

    /**
     * Resolve the ID token issuer for the carbon context the validator sets up.
     */
    private String resolveIdTokenIssuer(boolean isMtlsRequest) {

        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        issuerResidentOrganizationId = carbonContext.getApplicationResidentOrganizationId();
        issuerContextUsername = carbonContext.getUsername();
        assertEquals(carbonContext.getTenantDomain(), TENANT_DOMAIN);
        assertEquals(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT), TENANT_DOMAIN);
        if (ORG_ID.equals(carbonContext.getApplicationResidentOrganizationId())) {
            return oAuthAppDO.getIssuerDetails() != null ? ORG_ISSUER : ISSUER;
        }
        return isMtlsRequest ? MTLS_ISSUER : ISSUER;
    }

    private AuthenticatedUser validate(String token) throws Exception {

        return validator.validateAndGetUser(token, context, DEFAULT_MAX_TOKEN_AGE_SECONDS);
    }

    private void assertClientError(String token) {

        assertClientError(token, ERROR_CODE_INVALID_TOKEN);
    }

    private void assertClientError(String token, ErrorMessages error) {

        assertClientError(token, error, error.getDescription());
    }

    private void assertClientError(String token, ErrorMessages error, String description) {

        FlowEngineClientException exception = expectThrows(FlowEngineClientException.class,
                () -> validator.validateAndGetUser(token, context, DEFAULT_MAX_TOKEN_AGE_SECONDS));
        assertEquals(exception.getErrorCode(), error.getCode());
        assertEquals(exception.getMessage(), error.getMessage());
        assertEquals(exception.getDescription(), description);
    }

    private String buildToken(Consumer<JWTClaimsSet.Builder> customizer) throws Exception {

        return buildToken(customizer, keyPair);
    }

    private String buildToken(Consumer<JWTClaimsSet.Builder> customizer, KeyPair signingKeyPair) throws Exception {

        long now = System.currentTimeMillis();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .audience(Arrays.asList(CLIENT_ID, USER_VERIFICATION_AUDIENCE))
                .claim(OAuthConstants.OIDCClaims.AZP, CLIENT_ID)
                .issueTime(new Date(now))
                .notBeforeTime(new Date(now))
                .expirationTime(new Date(now + 3_600_000));
        customizer.accept(builder);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), builder.build());
        signedJWT.sign(new RSASSASigner(signingKeyPair.getPrivate()));
        return signedJWT.serialize();
    }

    private Certificate buildCertificate(KeyPair certificateKeyPair) {

        Certificate certificate = mock(Certificate.class);
        when(certificate.getPublicKey()).thenReturn(certificateKeyPair.getPublic());
        return certificate;
    }

    private AuthenticatedUser buildUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserId(USER_ID);
        user.setUserName(USER_NAME);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(TENANT_DOMAIN);
        return user;
    }

    /**
     * Build a user resolved in the organization, with the organization the user resides in.
     */
    private AuthenticatedUser buildOrganizationUser(String userResidentOrganizationId) {

        AuthenticatedUser user = buildUser();
        user.setUserResidentOrganization(userResidentOrganizationId);
        return user;
    }
}
