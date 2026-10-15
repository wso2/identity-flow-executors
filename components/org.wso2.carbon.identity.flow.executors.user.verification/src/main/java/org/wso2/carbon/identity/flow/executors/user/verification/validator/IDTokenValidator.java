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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
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
import org.wso2.carbon.identity.oauth2.IDTokenValidationFailureException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.config.models.IssuerDetails;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.TENANT_NAME_FROM_CONTEXT;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.TokenTypes.ID_TOKEN_TYPE;
import static org.wso2.carbon.identity.flow.executors.user.verification.constant.UserVerificationConstants.USER_VERIFICATION_AUDIENCE;
import static org.wso2.carbon.identity.flow.executors.user.verification.util.UserVerificationUtils.handleClientException;

/**
 * Validates an OpenID Connect ID token and resolves its user.
 */
public class IDTokenValidator implements UserVerificationTokenValidator {

    private static final Log LOG = LogFactory.getLog(IDTokenValidator.class);
    private static final String MUTUAL_TLS_ALIASES_ENABLED = "OAuth.MutualTLSAliases.Enabled";

    @Override
    public String getTokenType() {

        return ID_TOKEN_TYPE;
    }

    @Override
    public AuthenticatedUser validateAndGetUser(String token, FlowExecutionContext context, long maxTokenAge)
            throws FlowEngineClientException, FlowEngineServerException {

        try {
            String tenantDomain = context.getTenantDomain();
            SignedJWT signedJWT = parseIdToken(token);
            JWTClaimsSet claimsSet = getClaimsSet(signedJWT);
            validateMandatoryClaims(claimsSet);
            String clientId = getClientId(claimsSet);
            validateAudience(claimsSet, clientId);

            OAuthAppDO oAuthAppDO = getOAuthApp(clientId, tenantDomain);
            String appTenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
            String appRootTenantDomain = getRootTenantDomain(appTenantDomain);
            validateSignature(signedJWT, oAuthAppDO, appRootTenantDomain);
            validateIssuer(claimsSet, clientId, appTenantDomain, appRootTenantDomain, tenantDomain);
            validateTimestamps(claimsSet, maxTokenAge);
            AuthenticatedUser user = resolveUser(claimsSet.getSubject(), tenantDomain, appTenantDomain, clientId);
            if (user == null) {
                LOG.debug("ID token subject could not be resolved to a user in the organization.");
                throw handleClientException(ErrorMessages.ERROR_CODE_USER_NOT_FOUND, tenantDomain);
            }
            return user;
        } catch (IDTokenValidationFailureException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("ID token validation failed: " + e.getMessage());
            }
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_TOKEN);
        } catch (IdentityOAuth2Exception e) {
            throw new FlowEngineServerException(null, "Error while validating the ID token.", null, e);
        }
    }

    private SignedJWT parseIdToken(String idToken) throws IDTokenValidationFailureException {

        try {
            IdentityUtil.validateJWTDepth(idToken);
            return SignedJWT.parse(idToken);
        } catch (ParseException e) {
            throw new IDTokenValidationFailureException("ID token could not be parsed.");
        }
    }

    private JWTClaimsSet getClaimsSet(SignedJWT signedJWT) throws IDTokenValidationFailureException {

        try {
            return signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new IDTokenValidationFailureException("ID token claims could not be parsed.");
        }
    }

    private void validateMandatoryClaims(JWTClaimsSet claimsSet) throws IDTokenValidationFailureException {

        try {
            JWTUtils.validateMandatoryClaims(claimsSet);
        } catch (IdentityOAuth2Exception e) {
            throw new IDTokenValidationFailureException(e.getMessage());
        }
    }

    private String getClientId(JWTClaimsSet claimsSet) throws IDTokenValidationFailureException {

        Object azp = claimsSet.getClaim(OAuthConstants.OIDCClaims.AZP);
        if (azp == null || StringUtils.isBlank(azp.toString())) {
            throw new IDTokenValidationFailureException("ID token azp is missing.");
        }
        return azp.toString();
    }

    /**
     * Get the application of the client from the organization hierarchy of the flow's tenant.
     */
    private OAuthAppDO getOAuthApp(String clientId, String tenantDomain) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO;
        try {
            String orgId = UserVerificationDataHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            oAuthAppDO = OAuth2Util.getAppInformationFromOrgHierarchy(clientId, orgId);
        } catch (InvalidOAuthClientException e) {
            throw new IDTokenValidationFailureException("No OAuth application found for the ID token client ID.");
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while resolving the organization of the tenant: "
                    + tenantDomain, e);
        }
        if (oAuthAppDO == null) {
            throw new IDTokenValidationFailureException("No OAuth application found for the ID token client ID.");
        }
        return oAuthAppDO;
    }

    /**
     * Validate the ID token signature with the signing tenant's key.
     */
    private void validateSignature(SignedJWT signedJWT, OAuthAppDO oAuthAppDO, String appRootTenantDomain)
            throws IdentityOAuth2Exception {

        String signingTenantDomain = resolveSigningTenantDomain(oAuthAppDO, appRootTenantDomain);
        if (StringUtils.isEmpty(signingTenantDomain)) {
            throw new IDTokenValidationFailureException("Signing tenant domain could not be resolved.");
        }
        try {
            RSAPublicKey publicKey = (RSAPublicKey) OAuth2Util.getCertificate(signingTenantDomain).getPublicKey();
            if (!signedJWT.verify(new RSASSAVerifier(publicKey))) {
                throw new IDTokenValidationFailureException("ID token signature validation failed.");
            }
        } catch (JOSEException e) {
            throw new IDTokenValidationFailureException("ID token signature could not be validated.");
        }
    }

    /**
     * Validate that the audience contains the client ID and the user verification audience.
     */
    private void validateAudience(JWTClaimsSet claimsSet, String clientId)
            throws IDTokenValidationFailureException, FlowEngineClientException {

        List<String> audience = claimsSet.getAudience();
        if (!audience.contains(clientId)) {
            throw new IDTokenValidationFailureException("ID token audience does not contain the client ID.");
        }
        if (!audience.contains(USER_VERIFICATION_AUDIENCE)) {
            LOG.debug("ID token audience does not contain the user verification audience.");
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_TOKEN_AUDIENCE);
        }
    }

    /**
     * Resolve the tenant whose key signs the application's ID tokens: the application's token issuer organization,
     * otherwise the root tenant.
     */
    private String resolveSigningTenantDomain(OAuthAppDO oAuthAppDO, String appRootTenantDomain) {

        IssuerDetails issuerDetails = oAuthAppDO.getIssuerDetails();
        if (issuerDetails != null && StringUtils.isNotEmpty(issuerDetails.getIssuerTenantDomain())) {
            return issuerDetails.getIssuerTenantDomain();
        }
        return appRootTenantDomain;
    }

    /**
     * Validate that the issuer is one of the application's ID token issuers.
     */
    private void validateIssuer(JWTClaimsSet claimsSet, String clientId, String appTenantDomain,
                                String appRootTenantDomain, String tenantDomain) throws IdentityOAuth2Exception {

        String issuer = claimsSet.getIssuer();
        boolean isRootApp = appRootTenantDomain.equals(appTenantDomain);
        if (!getIdTokenIssuers(clientId, isRootApp, appRootTenantDomain, tenantDomain).contains(issuer)) {
            throw new IDTokenValidationFailureException("ID token issuer is invalid.");
        }
    }

    /**
     * Get the root tenant domain of the given tenant.
     */
    private String getRootTenantDomain(String tenantDomain) throws IdentityOAuth2Exception {

        OrganizationManager organizationManager = UserVerificationDataHolder.getInstance().getOrganizationManager();
        try {
            String orgId = organizationManager.resolveOrganizationId(tenantDomain);
            return organizationManager.resolveTenantDomain(organizationManager.getPrimaryOrganizationId(orgId));
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while resolving the root organization of the tenant: "
                    + tenantDomain, e);
        }
    }

    /**
     * Get the application's ID token issuers. For a root application used in an organization, the carbon context
     * is switched to the root tenant, where its tokens are issued.
     */
    private List<String> getIdTokenIssuers(String clientId, boolean isRootApp, String appRootTenantDomain,
                                           String tenantDomain) throws IdentityOAuth2Exception {

        if (!isRootApp || appRootTenantDomain.equals(tenantDomain)) {
            return buildIdTokenIssuers(clientId, appRootTenantDomain);
        }

        Object prevThreadLocalTenant = IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT);
        Object prevRootTenant = IdentityUtil.threadLocalProperties.get()
                .get(OrganizationManagementConstants.ROOT_TENANT_DOMAIN);
        PrivilegedCarbonContext.startTenantFlow();
        try {
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(appRootTenantDomain);
            IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, appRootTenantDomain);
            IdentityUtil.threadLocalProperties.get().put(OrganizationManagementConstants.ROOT_TENANT_DOMAIN, null);
            return buildIdTokenIssuers(clientId, appRootTenantDomain);
        } finally {
            IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, prevThreadLocalTenant);
            IdentityUtil.threadLocalProperties.get().put(OrganizationManagementConstants.ROOT_TENANT_DOMAIN,
                    prevRootTenant);
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    /**
     * Build the application's ID token issuers, with the mutual TLS issuer when mutual TLS aliases are enabled.
     */
    private List<String> buildIdTokenIssuers(String clientId, String appRootTenantDomain)
            throws IdentityOAuth2Exception {

        List<String> issuers = new ArrayList<>();
        issuers.add(OAuth2Util.getIdTokenIssuer(appRootTenantDomain, clientId, false));
        if (Boolean.parseBoolean(IdentityUtil.getProperty(MUTUAL_TLS_ALIASES_ENABLED))) {
            issuers.add(OAuth2Util.getIdTokenIssuer(appRootTenantDomain, clientId, true));
        }
        return issuers;
    }

    /**
     * Validate exp, nbf, and iat against maxTokenAge, applying the clock skew.
     */
    private void validateTimestamps(JWTClaimsSet claimsSet, long maxTokenAge)
            throws IDTokenValidationFailureException, FlowEngineClientException {

        if (!JWTUtils.checkExpirationTime(claimsSet.getExpirationTime())) {
            throw handleClientException(ErrorMessages.ERROR_CODE_TOKEN_EXPIRED);
        }
        try {
            JWTUtils.checkNotBeforeTime(claimsSet.getNotBeforeTime());
        } catch (IdentityOAuth2Exception e) {
            throw new IDTokenValidationFailureException(e.getMessage());
        }
        Date issueTime = claimsSet.getIssueTime();
        if (issueTime == null) {
            throw new IDTokenValidationFailureException("ID token iat is missing.");
        }
        long now = System.currentTimeMillis();
        long skewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        if (now + skewMillis - issueTime.getTime() > maxTokenAge * 1000) {
            LOG.debug("ID token is older than the max token age.");
            throw handleClientException(ErrorMessages.ERROR_CODE_TOKEN_ISSUED_BEFORE_ALLOWED_TIME);
        }
    }

    /**
     * Resolve the user from the subject by the application's subject claim, then by the default subject. In an
     * organization, only users that reside in the organization are resolved. Null if not found.
     */
    private AuthenticatedUser resolveUser(String subject, String tenantDomain, String appTenantDomain,
                                          String clientId) throws IdentityOAuth2Exception {

        OrganizationManager organizationManager = UserVerificationDataHolder.getInstance().getOrganizationManager();
        String orgId;
        String rootOrgId;
        try {
            orgId = organizationManager.resolveOrganizationId(tenantDomain);
            rootOrgId = organizationManager.getPrimaryOrganizationId(orgId);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while resolving the organization of the tenant: "
                    + tenantDomain, e);
        }
        boolean isOrganization = !rootOrgId.equals(orgId);
        AuthenticatedUser user = null;
        try {
            if (isOrganization) {
                user = OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(subject, appTenantDomain, orgId, orgId,
                        clientId);
            } else {
                user = OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(subject, tenantDomain, clientId);
            }
        } catch (IdentityOAuth2Exception e) {
            LOG.debug("Could not resolve the user by the application's subject claim. Retrying with the default "
                    + "subject.");
        }
        if (user == null) {
            try {
                if (isOrganization) {
                    user = OAuth2Util.getAuthenticatedUser(subject, appTenantDomain, orgId, orgId, clientId);
                } else {
                    user = OAuth2Util.getAuthenticatedUser(subject, tenantDomain, clientId);
                }
            } catch (IdentityOAuth2Exception e) {
                LOG.debug("Could not resolve the user by the default subject.");
                return null;
            }
        }
        if (user != null && isOrganization && !orgId.equals(user.getUserResidentOrganization())) {
            LOG.debug("The user does not reside in the organization of the flow.");
            return null;
        }
        return user;
    }
}
