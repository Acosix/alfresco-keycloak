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
package de.acosix.alfresco.keycloak.repo.client;

import java.util.function.Consumer;

import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * Instances of this interface wrap the relevant Keycloak admin ReST API for the synchronisation of users and groups from a Keycloak realm.
 *
 * @author Axel Faust
 */
public interface IdentitiesClient
{

    /**
     * Retrieves the number of users within the Keycloak IDM database.
     *
     * @return the count of users in the Keycloak database
     */
    int countUsers();

    /**
     * Retrieves the number of groups within the Keycloak IDM database.
     *
     * @return the count of groups in the Keycloak database
     */
    int countGroups();

    /**
     * Retrieves the details of one specific group from Keycloak.
     *
     * @param groupId
     *     the ID of the group in Keycloak
     * @return the group details
     */
    GroupRepresentation getGroup(String groupId);

    /**
     * Loads and processes a batch of users from Keycloak using an externally specified processor.
     *
     * @param offset
     *     the index of the first user to retrieve
     * @param userBatchSize
     *     the number of users to load in one batch
     * @param userProcessor
     *     the processor handling the loaded users
     * @return the number of processed users
     */
    int processUsers(int offset, int userBatchSize, Consumer<UserRepresentation> userProcessor);

    /**
     * Loads and processes a batch of groups of a specific user from Keycloak using an externally specified processor.
     *
     * @param userId
     *     the ID of user for which to process groups
     * @param offset
     *     the index of the first group to retrieve
     * @param groupBatchSize
     *     the number of groups to load in one batch
     * @param groupProcessor
     *     the processor handling the loaded groups
     * @return the number of processed groups
     */
    int processUserGroups(String userId, int offset, int groupBatchSize, Consumer<GroupRepresentation> groupProcessor);

    /**
     * Loads and processes a batch of groups from Keycloak using an externally specified processor.
     *
     * @param offset
     *     the index of the first group to retrieve
     * @param groupBatchSize
     *     the number of groups to load in one batch
     * @param groupProcessor
     *     the processor handling the loaded groups
     * @return the number of processed groups
     */
    int processGroups(int offset, int groupBatchSize, Consumer<GroupRepresentation> groupProcessor);

    /**
     * Loads and processes a sub-groups from Keycloak using an externally specified processor.
     *
     * @param groupId
     *     the ID of the parent group
     * @param groupProcessor
     *     the processor handling the loaded groups
     * @return the number of processed groups
     */
    int processSubGroups(String groupId, Consumer<GroupRepresentation> groupProcessor);

    /**
     * Loads and processes a batch of users / members of a group from Keycloak using an externally specified processor.
     *
     * @param groupId
     *     the ID of group for which to process members
     * @param offset
     *     the index of the first user to retrieve
     * @param userBatchSize
     *     the number of users to load in one batch
     * @param userProcessor
     *     the processor handling the loaded users
     * @return the number of processed users
     */
    int processMembers(String groupId, int offset, int userBatchSize, Consumer<UserRepresentation> userProcessor);

}
