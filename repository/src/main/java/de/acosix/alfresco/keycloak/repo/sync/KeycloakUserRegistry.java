/*
 * Copyright 2019 - 2021 Acosix GmbH
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
package de.acosix.alfresco.keycloak.repo.sync;

import java.util.AbstractCollection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.management.subsystems.ActivateableBean;
import org.alfresco.repo.security.sync.NodeDescription;
import org.alfresco.repo.security.sync.UserRegistry;
import org.alfresco.service.cmr.security.AuthorityType;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.PropertyCheck;
import org.alfresco.util.PropertyMap;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import de.acosix.alfresco.keycloak.repo.client.IDMClient;
import de.acosix.alfresco.keycloak.repo.client.IDMClientImpl;

/**
 * This class provides a Keycloak-based user registry to support synchronisation with Keycloak managed users and groups.
 *
 * @author Axel Faust
 */
public class KeycloakUserRegistry implements UserRegistry, InitializingBean, ActivateableBean, ApplicationContextAware
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakUserRegistry.class);

    protected boolean active;

    protected ApplicationContext applicationContext;

    protected IDMClient idmClient;

    protected Collection<UserFilter> userFilters;

    protected Collection<GroupFilter> groupFilters;

    protected Collection<UserProcessor> userProcessors;

    protected Collection<GroupProcessor> groupProcessors;

    protected int personLoadBatchSize = 50;

    protected int groupLoadBatchSize = 50;

    /**
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "applicationContext", this.applicationContext);
        PropertyCheck.mandatory(this, "idmClient", this.idmClient);

        this.userFilters = Collections.unmodifiableList(
                new ArrayList<>(this.applicationContext.getBeansOfType(UserFilter.class, false, true).values()));
        this.groupFilters = Collections.unmodifiableList(
                new ArrayList<>(this.applicationContext.getBeansOfType(GroupFilter.class, false, true).values()));
        this.userProcessors = Collections.unmodifiableList(
                new ArrayList<>(this.applicationContext.getBeansOfType(UserProcessor.class, false, true).values()));
        this.groupProcessors = Collections.unmodifiableList(
                new ArrayList<>(this.applicationContext.getBeansOfType(GroupProcessor.class, false, true).values()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isActive()
    {
        return this.active;
    }

    /**
     * @param active
     *            the active to set
     */
    public void setActive(final boolean active)
    {
        this.active = active;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setApplicationContext(final ApplicationContext applicationContext)
    {
        this.applicationContext = applicationContext;
    }

    /**
     * @param idmClient
     *            the idmClient to set
     */
    public void setIdmClient(final IDMClientImpl idmClient)
    {
        this.idmClient = idmClient;
    }

    /**
     * @param personLoadBatchSize
     *            the personLoadBatchSize to set
     */
    public void setPersonLoadBatchSize(final int personLoadBatchSize)
    {
        this.personLoadBatchSize = personLoadBatchSize;
    }

    /**
     * @param groupLoadBatchSize
     *            the groupLoadBatchSize to set
     */
    public void setGroupLoadBatchSize(final int groupLoadBatchSize)
    {
        this.groupLoadBatchSize = groupLoadBatchSize;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<NodeDescription> getPersons(final Date modifiedSince)
    {
        // Keycloak does not support any "modifiedSince" semantics

        Collection<NodeDescription> people = Collections.emptyList();

        if (this.active)
        {
            people = new UserCollection<>(this.personLoadBatchSize, this.idmClient.countUsers(), this::mapUser);
        }

        return people;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<NodeDescription> getGroups(final Date modifiedSince)
    {
        // Keycloak does not support any "modifiedSince" semantics

        Collection<NodeDescription> groups = Collections.emptySet();

        if (this.active)
        {
            groups = new GroupCollection<>(this.groupLoadBatchSize, this.idmClient.countGroups(), this::mapGroup);
        }

        return groups;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<String> getPersonNames()
    {
        Collection<String> personNames = Collections.emptySet();

        if (this.active)
        {
            personNames = new UserCollection<>(this.personLoadBatchSize, this.idmClient.countUsers(), UserRepresentation::getUsername);
        }

        return personNames;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<String> getGroupNames()
    {
        Collection<String> groupNames = Collections.emptySet();

        if (this.active)
        {
            groupNames = new GroupCollection<>(this.groupLoadBatchSize, this.idmClient.countGroups(),
                    group -> AuthorityType.GROUP.getPrefixString() + group.getId());
        }

        return groupNames;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<QName> getPersonMappedProperties()
    {
        final Set<QName> mappedProperties = new HashSet<>();

        this.userProcessors.stream().map(UserProcessor::getMappedProperties).forEach(mappedProperties::addAll);

        return mappedProperties;
    }

    /**
     * Maps a single user from the Keycloak representation into an abstract description of a person node.
     *
     * @param user
     *            the user to map
     * @return the mapped person node description
     */
    protected NodeDescription mapUser(final UserRepresentation user)
    {
        final NodeDescription person = new NodeDescription(user.getId());
        final PropertyMap personProperties = person.getProperties();

        LOGGER.debug("Mapping user {}", user.getUsername());

        this.userProcessors.forEach(processor -> processor.mapUser(user, person));

        // always wins against user-defined mappings for cm:userName
        personProperties.put(ContentModel.PROP_USERNAME, user.getUsername());

        return person;
    }

    /**
     * Maps a single group from the Keycloak representation into an abstract description of a group node.
     *
     * @param group
     *            the group to map
     * @return the mapped group node description
     */
    protected NodeDescription mapGroup(final GroupRepresentation group)
    {
        // need to use group ID as unique name as Keycloak group name itself is non-unique

        final NodeDescription groupD = new NodeDescription(group.getId());
        final PropertyMap groupProperties = groupD.getProperties();

        final String groupId = AuthorityType.GROUP.getPrefixString() + group.getId();
        LOGGER.debug("Mapping group {}", groupId);

        this.groupProcessors.forEach(processor -> processor.mapGroup(group, groupD));

        final Set<String> childAssociations = groupD.getChildAssociations();
        group.getSubGroups().stream()
                .filter(subGroup -> !this.groupFilters.stream().anyMatch(filter -> !filter.shouldIncludeGroup(subGroup)))
                .forEach(subGroup -> childAssociations.add(AuthorityType.GROUP.getPrefixString() + subGroup.getId()));

        int offset = 0;
        int processedMembers = 1;
        while (processedMembers > 0)
        {
            processedMembers = this.idmClient.processMembers(group.getId(), offset, this.personLoadBatchSize, user -> {
                final boolean skipSync = this.userFilters.stream().anyMatch(filter -> !filter.shouldIncludeUser(user));
                if (!skipSync)
                {
                    childAssociations.add(user.getUsername());
                }
            });
            offset += processedMembers;
        }

        LOGGER.debug("Mapped members of group {}: {}", groupId, childAssociations);

        return groupD;
    }

    /**
     * This class provides common basic functionalities for a collection of Keycloak authority-based data elements, supporting basic batch
     * load-based pagination / iterative traversal.
     *
     * @author Axel Faust
     */
    protected abstract class KeycloakAuthorityCollection<T, AR> extends AbstractCollection<T>
    {

        protected final int batchSize;

        protected final int totalUpperBound;

        protected final Function<AR, T> mapper;

        /**
         * Constructs a new instance of this class.
         *
         * @param batchSize
         *            the size of batches to use for incrementally loading data elements in the iterator
         * @param totalUpperBound
         *            the upper bound of the total number of elements to expect in this collection - this is just an estimation (without
         *            adjusting for any potential filtering) and will be used as the {@link #size() collection's size}.
         * @param mapper
         *            the mapping handler to turn a low-level authority representation into the actual collection value representation
         */
        protected KeycloakAuthorityCollection(final int batchSize, final int totalUpperBound, final Function<AR, T> mapper)
        {
            this.batchSize = batchSize;
            this.totalUpperBound = totalUpperBound;
            this.mapper = mapper;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int size()
        {
            return this.totalUpperBound;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Iterator<T> iterator()
        {
            return new KeycloakAuthorityIterator();
        }

        /**
         * Loads the next batch of authority representations.
         *
         * @param offset
         *            the index of the first low-level authority to load
         * @param batchSize
         *            the maximum number of low-level authorities to load from the backend
         * @param authorityProcessor
         *            the processor to consume individual authority representations - the number of representations passed to this processor
         *            may be different than the number of authorities loaded from the backend due to filtering and potential pre-processing
         *            (e.g. splitting of groups and sub-groups)
         * @return the number of low-level authorities loaded in this batch to properly adjust the offset for the next load operation
         */
        protected abstract int loadNext(int offset, int batchSize, Consumer<AR> authorityProcessor);

        /**
         * Converts an authority representation into the type of object to be exposed as values of the collection.
         *
         * @param authorityRepresentation
         *            the authority representation to convert
         * @return the converted value
         */
        protected T convert(final AR authorityRepresentation)
        {
            return this.mapper.apply(authorityRepresentation);
        }

        protected class KeycloakAuthorityIterator implements Iterator<T>
        {

            private final List<T> buffer = new ArrayList<>();

            private int offset;

            private int index;

            private boolean noMoreResults;

            /**
             * {@inheritDoc}
             */
            @Override
            public synchronized boolean hasNext()
            {
                this.checkAndFillBuffer();

                final boolean hasNext = !this.buffer.isEmpty() && this.index < this.buffer.size();
                return hasNext;
            }

            /**
             * {@inheritDoc}
             */
            @Override
            public synchronized T next()
            {
                this.checkAndFillBuffer();

                T next;
                if (!this.buffer.isEmpty() && this.index < this.buffer.size())
                {
                    next = this.buffer.get(this.index++);
                }
                else
                {
                    throw new NoSuchElementException();
                }
                return next;
            }

            protected synchronized void checkAndFillBuffer()
            {
                if ((this.buffer.isEmpty() || this.index >= this.buffer.size()) && !this.noMoreResults)
                {
                    this.buffer.clear();

                    this.index = 0;
                    this.offset += KeycloakAuthorityCollection.this.loadNext(this.offset, KeycloakAuthorityCollection.this.batchSize,
                            authority -> this.buffer.add(KeycloakAuthorityCollection.this.convert(authority)));

                    this.noMoreResults = this.buffer.isEmpty();
                }
            }
        }
    }

    /**
     * This class provides the basis for all user-related collections.
     *
     * @author Axel Faust
     */
    protected class UserCollection<T> extends KeycloakAuthorityCollection<T, UserRepresentation>
    {

        /**
         * Constructs a new instance of this class.
         *
         * @param batchSize
         *            the size of batches to use for incrementally loading data elements in the iterator
         * @param totalUpperBound
         *            the upper bound of the total number of elements to expect in this collection - this is just an estimation (without
         *            adjusting for any potential filtering) and will be used as the {@link #size() collection's size}.
         * @param mapper
         *            the mapping handler to turn a low-level authority representation into the actual collection value representation
         */
        public UserCollection(final int batchSize, final int totalUpperBound, final Function<UserRepresentation, T> mapper)
        {
            super(batchSize, totalUpperBound, mapper);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected int loadNext(final int offset, final int batchSize, final Consumer<UserRepresentation> authorityProcessor)
        {
            // TODO Evaluate other iteration approaches, e.g. crawling from a configured root group
            // How to count totals in advance though?
            return KeycloakUserRegistry.this.idmClient.processUsers(offset, batchSize, user -> {
                final boolean skipSync = KeycloakUserRegistry.this.userFilters.stream().anyMatch(filter -> !filter.shouldIncludeUser(user));
                if (!skipSync)
                {
                    authorityProcessor.accept(user);
                }
            });
        }

    }

    /**
     * This class provides the basis for all group-related collections.
     *
     * @author Axel Faust
     */
    protected class GroupCollection<T> extends KeycloakAuthorityCollection<T, GroupRepresentation>
    {

        /**
         * Constructs a new instance of this class.
         *
         * @param batchSize
         *            the size of batches to use for incrementally loading data elements in the iterator
         * @param totalUpperBound
         *            the upper bound of the total number of elements to expect in this collection - this is just an estimation (without
         *            adjusting for any potential filtering) and will be used as the {@link #size() collection's size}.
         * @param mapper
         *            the mapping handler to turn a low-level authority representation into the actual collection value representation
         */
        public GroupCollection(final int batchSize, final int totalUpperBound, final Function<GroupRepresentation, T> mapper)
        {
            super(batchSize, totalUpperBound, mapper);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected int loadNext(final int offset, final int batchSize, final Consumer<GroupRepresentation> authorityProcessor)
        {
            // TODO Evaluate other iteration approaches, e.g. crawling from a configured root group
            // How to count totals in advance though?
            return KeycloakUserRegistry.this.idmClient.processGroups(offset, batchSize, group -> {
                this.processGroupsRecursively(group, authorityProcessor);
            });
        }

        protected void processGroupsRecursively(final GroupRepresentation group, final Consumer<GroupRepresentation> authorityProcessor)
        {
            final boolean skipSync = KeycloakUserRegistry.this.groupFilters.stream().anyMatch(filter -> !filter.shouldIncludeGroup(group));
            if (!skipSync)
            {
                authorityProcessor.accept(group);
            }

            // any filtering applied above does not apply here as any sub-group will be individually checked for filtering by recursive
            // processing
            group.getSubGroups().forEach(subGroup -> this.processGroupsRecursively(subGroup, authorityProcessor));
        }
    }
}
