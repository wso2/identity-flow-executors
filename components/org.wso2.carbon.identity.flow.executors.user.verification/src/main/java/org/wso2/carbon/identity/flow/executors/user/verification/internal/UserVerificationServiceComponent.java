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

package org.wso2.carbon.identity.flow.executors.user.verification.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.executors.user.verification.UserVerificationExecutor;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountDisableService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi declarative services component which registers the user verification executors.
 */
@Component(
        name = "identity.flow.executors.user.verification.component",
        immediate = true)
public class UserVerificationServiceComponent {

    private static final Log LOG = LogFactory.getLog(UserVerificationServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            context.getBundleContext().registerService(Executor.class.getName(), new UserVerificationExecutor(),
                    null);
            LOG.debug("User verification executor service successfully activated.");
        } catch (Throwable e) {
            LOG.error("Error while initiating user verification executor service", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        LOG.debug("User verification executor service successfully deactivated.");
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        LOG.debug("Setting the Realm Service.");
        UserVerificationDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        LOG.debug("Unsetting the Realm Service.");
        UserVerificationDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "claim.metadata.management.service",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimMetadataManagementService"
    )
    protected void setClaimMetadataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        LOG.debug("Setting the Claim Metadata Management Service.");
        UserVerificationDataHolder.getInstance().setClaimMetadataManagementService(claimMetadataManagementService);
    }

    protected void unsetClaimMetadataManagementService(
            ClaimMetadataManagementService claimMetadataManagementService) {

        LOG.debug("Unsetting the Claim Metadata Management Service.");
        UserVerificationDataHolder.getInstance().setClaimMetadataManagementService(null);
    }

    @Reference(
            name = "organization.management.service",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager"
    )
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        LOG.debug("Setting the Organization Manager.");
        UserVerificationDataHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        LOG.debug("Unsetting the Organization Manager.");
        UserVerificationDataHolder.getInstance().setOrganizationManager(null);
    }

    @Reference(
            name = "org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService",
            service = AccountLockService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAccountLockService"
    )
    protected void setAccountLockService(AccountLockService accountLockService) {

        LOG.debug("Setting the Account Lock Service.");
        UserVerificationDataHolder.getInstance().setAccountLockService(accountLockService);
    }

    protected void unsetAccountLockService(AccountLockService accountLockService) {

        LOG.debug("Unsetting the Account Lock Service.");
        UserVerificationDataHolder.getInstance().setAccountLockService(null);
    }

    @Reference(
            name = "org.wso2.carbon.identity.handler.event.account.lock.service.AccountDisableService",
            service = AccountDisableService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAccountDisableService"
    )
    protected void setAccountDisableService(AccountDisableService accountDisableService) {

        LOG.debug("Setting the Account Disable Service.");
        UserVerificationDataHolder.getInstance().setAccountDisableService(accountDisableService);
    }

    protected void unsetAccountDisableService(AccountDisableService accountDisableService) {

        LOG.debug("Unsetting the Account Disable Service.");
        UserVerificationDataHolder.getInstance().setAccountDisableService(null);
    }
}
