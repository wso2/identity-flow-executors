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

import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountDisableService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Holds the OSGi services used by the user verification executors.
 */
public class UserVerificationDataHolder {

    private static final UserVerificationDataHolder INSTANCE = new UserVerificationDataHolder();

    private RealmService realmService;
    private ClaimMetadataManagementService claimMetadataManagementService;
    private OrganizationManager organizationManager;
    private AccountLockService accountLockService;
    private AccountDisableService accountDisableService;

    private UserVerificationDataHolder() {

    }

    public static UserVerificationDataHolder getInstance() {

        return INSTANCE;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public ClaimMetadataManagementService getClaimMetadataManagementService() {

        return claimMetadataManagementService;
    }

    public void setClaimMetadataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        this.claimMetadataManagementService = claimMetadataManagementService;
    }

    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }

    public AccountLockService getAccountLockService() {

        return accountLockService;
    }

    public void setAccountLockService(AccountLockService accountLockService) {

        this.accountLockService = accountLockService;
    }

    public AccountDisableService getAccountDisableService() {

        return accountDisableService;
    }

    public void setAccountDisableService(AccountDisableService accountDisableService) {

        this.accountDisableService = accountDisableService;
    }
}
