/*
 * Copyright 2019 - 2025 Acosix GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.acosix.alfresco.keycloak.repo.roles;

import java.util.List;

import org.alfresco.repo.jscript.BaseScopableProcessorExtension;
import org.alfresco.util.PropertyCheck;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;
import org.springframework.beans.factory.InitializingBean;

/**
 * This service exposes mapped Keycloak roles to scripts running within the Repository-tier script processor, e.g. web script controllers.
 *
 * @author Axel Faust
 */
public class ScriptRoleService extends BaseScopableProcessorExtension implements InitializingBean
{

    protected RoleService roleService;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "roleService", this.roleService);
    }

    /**
     * @param roleService
     *            the roleService to set
     */
    public void setRoleService(final RoleService roleService)
    {
        this.roleService = roleService;
    }

    /**
     * Retrieves roles in the main realm and/or resource scopes (as far as possible based on configuration).
     *
     * @return the list of roles
     */
    public Scriptable listRoles()
    {
        final List<Role> roles = this.roleService.listRoles();
        final Scriptable roleArray = this.makeRoleArray(roles);
        return roleArray;
    }

    /**
     * Finds matching roles in the main realm and/or resource scopes (as far as possible based on configuration).
     *
     * @param shortNameFilter
     *            name pattern on which to filter groups - the filter will be applied on both the original Keycloak and the mapped Alfresco
     *            role name, and a match in either will result the role to be considered a match
     * @return the list of matching roles
     */
    public Scriptable findRoles(final String shortNameFilter)
    {
        final List<Role> roles = this.roleService.findRoles(shortNameFilter);
        final Scriptable roleArray = this.makeRoleArray(roles);
        return roleArray;
    }

    /**
     * Retrieves roles in the main realm and/or resource scopes (as far as possible based on configuration).
     *
     * @param realmOnly
     *            {@code true} if the list operation should only consider the main realm, or {@code false} if both realm and resource
     *            scopes are allowed to be listed
     *
     * @return the list of roles
     */
    public Scriptable listRoles(final boolean realmOnly)
    {
        final List<Role> roles = this.roleService.listRoles(realmOnly);
        final Scriptable roleArray = this.makeRoleArray(roles);
        return roleArray;
    }

    /**
     * Finds matching roles in the main realm and/or resource scopes (as far as possible based on configuration).
     *
     * @param shortNameFilter
     *            name pattern on which to filter groups - the filter will be applied on both the original Keycloak and the mapped Alfresco
     *            role name, and a match in either will result the role to be considered a match
     * @param realmOnly
     *            {@code true} if the search operation should only consider the main realm, or {@code false} if both realm and resource
     *            scopes are allowed to be searched
     * @return the list of matching roles
     */
    public Scriptable findRoles(final String shortNameFilter, final boolean realmOnly)
    {
        final List<Role> roles = this.roleService.findRoles(shortNameFilter, realmOnly);
        final Scriptable roleArray = this.makeRoleArray(roles);
        return roleArray;
    }

    /**
     * Retrieves roles in a specific resource scope (as far as possible based on configuration).
     *
     * @param resourceName
     *            the name of the resource for which to retrieve roles
     *
     * @return the list of roles
     */
    public Scriptable listRoles(final String resourceName)
    {
        final List<Role> roles = this.roleService.listRoles(resourceName);
        final Scriptable roleArray = this.makeRoleArray(roles);
        return roleArray;
    }

    /**
     * Finds matching roles in a specific resource scope (as far as possible based on configuration).
     *
     * @param resourceName
     *            the name of the resource for which to retrieve roles
     * @param shortNameFilter
     *            name pattern on which to filter groups - the filter will be applied on both the original Keycloak and the mapped Alfresco
     *            role name, and a match in either will result the role to be considered a match
     * @return the list of matching roles
     */
    public Scriptable findRoles(final String resourceName, final String shortNameFilter)
    {
        final List<Role> roles = this.roleService.findRoles(resourceName, shortNameFilter);
        final Scriptable roleArray = this.makeRoleArray(roles);
        return roleArray;
    }

    /**
     * Checks whether the specified authority name is a role mapped from Keycloak.
     *
     * @param authorityName
     *            the Alfresco authority name to check
     * @return {@code true} if the authority name matches any expected patterns of roles mapped from Keycloak, {@code false} otherwise
     */
    public boolean isMappedFromKeycloak(final String authorityName)
    {
        return this.roleService.isMappedFromKeycloak(authorityName);
    }

    /**
     * Retrieves the name of the client the specified authority name was mapped from within Keycloak.
     *
     * @param authorityName
     *            the Alfresco authority name to process
     * @return the name of the client which defines the role unless the role is either not mapped from Keycloak or mapped from the realm
     *         scope
     */
    public String getClientFromRole(final String authorityName)
    {
        return this.roleService.getClientFromRole(authorityName).orElse(null);
    }

    protected Scriptable makeRoleArray(final List<Role> roles)
    {
        final Scriptable sitesArray = Context.getCurrentContext().newArray(this.getScope(), roles.toArray(new Object[0]));
        return sitesArray;
    }
}
