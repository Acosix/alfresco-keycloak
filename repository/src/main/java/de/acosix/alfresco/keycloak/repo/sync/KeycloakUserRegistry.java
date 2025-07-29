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
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntConsumer;
import java.util.function.Predicate;

import org.alfresco.error.AlfrescoRuntimeException;
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

import de.acosix.alfresco.keycloak.repo.client.IdentitiesClient;

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

    protected IdentitiesClient identitiesClient;

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
        PropertyCheck.mandatory(this, "identitiesClient", this.identitiesClient);

        this.userFilters = Collections
                .unmodifiableList(new ArrayList<>(this.applicationContext.getBeansOfType(UserFilter.class, false, true).values()));
        this.groupFilters = Collections
                .unmodifiableList(new ArrayList<>(this.applicationContext.getBeansOfType(GroupFilter.class, false, true).values()));
        this.userProcessors = Collections
                .unmodifiableList(new ArrayList<>(this.applicationContext.getBeansOfType(UserProcessor.class, false, true).values()));
        this.groupProcessors = Collections
                .unmodifiableList(new ArrayList<>(this.applicationContext.getBeansOfType(GroupProcessor.class, false, true).values()));
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
     *     the active to set
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
     * @param identitiesClient
     *     the identitiesClient to set
     */
    public void setIdentitiesClient(final IdentitiesClient identitiesClient)
    {
        this.identitiesClient = identitiesClient;
    }

    /**
     * @param personLoadBatchSize
     *     the personLoadBatchSize to set
     */
    public void setPersonLoadBatchSize(final int personLoadBatchSize)
    {
        this.personLoadBatchSize = personLoadBatchSize;
    }

    /**
     * @param groupLoadBatchSize
     *     the groupLoadBatchSize to set
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
            people = new UserCollection<>(this.personLoadBatchSize, this.identitiesClient.countUsers(), this::mapUser);
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
            groups = new GroupCollection<>(this.groupLoadBatchSize, this.identitiesClient.countGroups(), this::mapGroup);
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
            personNames = new UserCollection<>(this.personLoadBatchSize, this.identitiesClient.countUsers(),
                    this::determineEffectiveUserName);
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
            groupNames = new GroupCollection<>(this.groupLoadBatchSize, this.identitiesClient.countGroups(),
                    this::determineEffectiveGroupName);
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
     *     the user to map
     * @return the mapped person node description
     */
    protected NodeDescription mapUser(final UserRepresentation user)
    {
        final NodeDescription person = new NodeDescription(user.getId());

        LOGGER.debug("Mapping user {} ({})", user.getUsername(), user.getId());

        // reverse ordered so higher priority mappers may override properties of lower priority ones
        this.userProcessors.stream().sorted((o1, o2) -> -o1.compareTo(o2)).forEach(processor -> processor.mapUser(user, person));

        final PropertyMap personProperties = person.getProperties();
        final String userName = this.determineEffectiveUserName(user);
        personProperties.put(ContentModel.PROP_USERNAME, userName);

        LOGGER.debug("Mapped user {} ({}) as {}", user.getUsername(), user.getId(), userName);

        return person;
    }

    /**
     * Maps a single group from the Keycloak representation into an abstract description of a group node.
     *
     * @param group
     *     the group to map
     * @return the mapped group node description
     */
    protected NodeDescription mapGroup(final GroupRepresentation group)
    {
        final NodeDescription groupD = new NodeDescription(group.getId());

        LOGGER.debug("Mapping group {} ({})", group.getName(), group.getId());

        this.groupProcessors.forEach(processor -> processor.mapGroup(group, groupD));

        final PropertyMap groupProperties = groupD.getProperties();
        final String groupName = this.determineEffectiveGroupName(group);
        groupProperties.put(ContentModel.PROP_AUTHORITY_NAME, groupName);

        LOGGER.debug("Mapped group {} ({}) as {}", group.getName(), group.getId(), groupName);

        final Set<String> childAssociations = groupD.getChildAssociations();
        group.getSubGroups().stream().filter(subGroup -> isGroupAllowed(this.groupFilters, subGroup))
                .forEach(subGroup -> childAssociations.add(this.determineEffectiveGroupName(subGroup)));

        int offset = 0;
        int processedMembers = 1;
        while (processedMembers > 0)
        {
            processedMembers = this.identitiesClient.processMembers(group.getId(), offset, this.personLoadBatchSize, user -> {
                if (KeycloakUserRegistry.isUserAllowed(this.userFilters, user))
                {
                    childAssociations.add(this.determineEffectiveUserName(user));
                }
            });
            offset += processedMembers;
        }

        LOGGER.debug("Mapped members of group {}: {}", groupName, childAssociations);

        return groupD;
    }

    private String determineEffectiveUserName(final UserRepresentation user)
    {
        final List<String> userNameCandidates = this.userProcessors.stream().sorted().map(gp -> gp.mapUserName(user))
                .filter(Predicate.not(Optional::isEmpty)).map(Optional::get).toList();

        String userName = userNameCandidates.isEmpty() ? null : userNameCandidates.get(0);
        if (userName == null || userName.isBlank())
        {
            // should never happen due to DefaultPersonProcessor
            userName = user.getUsername();
        }
        return userName;
    }

    private String determineEffectiveGroupName(final GroupRepresentation group)
    {
        final List<String> groupNameCandidates = this.groupProcessors.stream().sorted().map(gp -> gp.mapGroupName(group))
                .filter(Predicate.not(Optional::isEmpty)).map(Optional::get).toList();

        String groupName = groupNameCandidates.isEmpty() ? null : groupNameCandidates.get(0);
        if (groupName == null || groupName.isBlank())
        {
            // should never happen due to DefaultGroupProcessor
            groupName = group.getId();
        }

        // make sure groupName is prefixed
        if (AuthorityType.getAuthorityType(groupName) != AuthorityType.GROUP)
        {
            groupName = AuthorityType.GROUP.getPrefixString() + groupName;
        }
        return groupName;
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
         *     the size of batches to use for incrementally loading data elements in the iterator
         * @param totalUpperBound
         *     the upper bound of the total number of elements to expect in this collection - this is just an estimation (without
         *     adjusting for any potential filtering) and will be used as the {@link #size() collection's size}.
         * @param mapper
         *     the mapping handler to turn a low-level authority representation into the actual collection value representation
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
         *     the index of the first low-level authority to load
         * @param batchSize
         *     the maximum number of low-level authorities to load from the backend
         * @param filteredCountHandler
         *     a handler aggregating the count of entities filtered during loading
         * @param authorityProcessor
         *     the processor to consume individual authority representations - the number of representations passed to this processor
         *     may be different than the number of authorities loaded from the backend due to filtering and potential pre-processing
         *     (e.g. splitting of groups and sub-groups)
         * @return the number of low-level authorities loaded in this batch to properly adjust the offset for the next load operation
         */
        protected abstract int loadNext(int offset, int batchSize, IntConsumer filteredCountHandler, Consumer<AR> authorityProcessor);

        /**
         * Converts an authority representation into the type of object to be exposed as values of the collection.
         *
         * @param authorityRepresentation
         *     the authority representation to convert
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

            protected final AtomicInteger totalFiltered = new AtomicInteger(0);

            /**
             * {@inheritDoc}
             */
            @Override
            public synchronized boolean hasNext()
            {
                this.checkAndFillBuffer();

                final boolean hasNext = !this.buffer.isEmpty() && this.index < this.buffer.size();

                if (!hasNext && this.totalFiltered.get() > 0)
                {
                    LOGGER.info("End of collection reached - {} from total count of {} not processed due to configured post-fetch filters",
                            this.totalFiltered, KeycloakAuthorityCollection.this.totalUpperBound);
                }

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
                            i -> this.totalFiltered.addAndGet(i),
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
         *     the size of batches to use for incrementally loading data elements in the iterator
         * @param totalUpperBound
         *     the upper bound of the total number of elements to expect in this collection - this is just an estimation (without
         *     adjusting for any potential filtering) and will be used as the {@link #size() collection's size}.
         * @param mapper
         *     the mapping handler to turn a low-level authority representation into the actual collection value representation
         */
        public UserCollection(final int batchSize, final int totalUpperBound, final Function<UserRepresentation, T> mapper)
        {
            super(batchSize, totalUpperBound, mapper);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected int loadNext(final int offset, final int batchSize, final IntConsumer filteredHandler,
                final Consumer<UserRepresentation> authorityProcessor)
        {
            // TODO Evaluate other iteration approaches, e.g. crawling from a configured root group
            // How to count totals in advance though?
            return KeycloakUserRegistry.this.identitiesClient.processUsers(offset, batchSize, user -> {
                if (KeycloakUserRegistry.isUserAllowed(KeycloakUserRegistry.this.userFilters, user))
                {
                    authorityProcessor.accept(user);
                }
                else
                {
                    filteredHandler.accept(1);
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
         *     the size of batches to use for incrementally loading data elements in the iterator
         * @param totalUpperBound
         *     the upper bound of the total number of elements to expect in this collection - this is just an estimation (without
         *     adjusting for any potential filtering) and will be used as the {@link #size() collection's size}.
         * @param mapper
         *     the mapping handler to turn a low-level authority representation into the actual collection value representation
         */
        public GroupCollection(final int batchSize, final int totalUpperBound, final Function<GroupRepresentation, T> mapper)
        {
            super(batchSize, totalUpperBound, mapper);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected int loadNext(final int offset, final int batchSize, final IntConsumer filteredHandler,
                final Consumer<GroupRepresentation> authorityProcessor)
        {
            // TODO Evaluate other iteration approaches, e.g. crawling from a configured root group
            // How to count totals in advance though?
            final AtomicInteger count = new AtomicInteger();
            final int loadedDirect = KeycloakUserRegistry.this.identitiesClient.processGroups(offset, batchSize, group -> {
                this.processGroupsRecursively(group, filteredHandler, authorityProcessor, count);
            });
            return count.addAndGet(loadedDirect);
        }

        protected void processGroupsRecursively(final GroupRepresentation group, final IntConsumer filteredHandler,
                final Consumer<GroupRepresentation> authorityProcessor, final AtomicInteger count)
        {
            if (KeycloakUserRegistry.isGroupAllowed(KeycloakUserRegistry.this.groupFilters, group))
            {
                authorityProcessor.accept(group);
            }
            else
            {
                filteredHandler.accept(1);
            }

            final List<GroupRepresentation> subGroups = group.getSubGroups();
            if (subGroups == null || subGroups.isEmpty())
            {
                final List<GroupRepresentation> newSubGroups = new ArrayList<>();
                group.setSubGroups(newSubGroups);
                try
                {
                    final int loadedChilren = KeycloakUserRegistry.this.identitiesClient.processSubGroups(group.getId(), subGroup -> {
                        newSubGroups.add(subGroup);
                        this.processGroupsRecursively(subGroup, filteredHandler, authorityProcessor, count);
                    });
                    count.addAndGet(loadedChilren);
                }
                catch (final AlfrescoRuntimeException ex)
                {
                    LOGGER.warn("Failed to load sub groups for {} ({})", group.getName(), group.getId(), ex);
                }
            }
            else
            {
                subGroups.stream().forEach(subGroup -> this.processGroupsRecursively(subGroup, filteredHandler, authorityProcessor, count));
                count.addAndGet(subGroups.size());
            }
        }
    }

    private static boolean isUserAllowed(final Collection<UserFilter> filters, final UserRepresentation user)
    {
        final FilterResult res = filters.stream().map(f -> f.shouldIncludeUser(user)).reduce(KeycloakUserRegistry::combine)
                .orElse(FilterResult.ABSTAIN);
        return res == FilterResult.ALLOW;
    }

    private static boolean isGroupAllowed(final Collection<GroupFilter> filters, final GroupRepresentation group)
    {
        final FilterResult res = filters.stream().map(f -> f.shouldIncludeGroup(group)).reduce(KeycloakUserRegistry::combine)
                .orElse(FilterResult.ABSTAIN);
        return res == FilterResult.ALLOW;
    }

    private static FilterResult combine(final FilterResult a, final FilterResult b)
    {
        FilterResult res;
        if (a == FilterResult.DENY || b == FilterResult.DENY)
        {
            res = FilterResult.DENY;
        }
        else if (a == FilterResult.ABSTAIN)
        {
            res = b;
        }
        else
        {
            res = a;
        }
        return res;
    }
}
