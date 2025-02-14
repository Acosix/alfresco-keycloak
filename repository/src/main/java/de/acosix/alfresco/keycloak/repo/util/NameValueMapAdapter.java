package de.acosix.alfresco.keycloak.repo.util;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;

import org.alfresco.error.AlfrescoRuntimeException;
import org.apache.http.NameValuePair;

public class NameValueMapAdapter<T extends NameValuePair> implements Map<String, String> {

    private final List<? extends NameValuePair> pairs;
    private final Class<T> type;

    public NameValueMapAdapter(List<? extends NameValuePair> pairs, Class<T> type) {
        this.pairs = pairs;
        this.type = type;
    }

    @Override
    public void clear() {
        this.pairs.clear();
    }

    @Override
    public boolean containsKey(Object key) {
        for (NameValuePair pair : this.pairs)
            if (pair.getName().equals(key))
                return true;
        return false;
    }

    @Override
    public boolean containsValue(Object value) {
        for (NameValuePair pair : this.pairs)
            if (pair.getValue().equals(value))
                return true;
        return false;
    }

    @Override
    public Set<Entry<String, String>> entrySet() {
        Set<Entry<String, String>> set = new HashSet<Entry<String, String>>();
        for (NameValuePair pair : this.pairs) {
            set.add(new Entry<String, String>() {
                @Override
                public String getKey() {
                    return pair.getName();
                }

                @Override
                public String getValue() {
                    return pair.getValue();
                }

                @Override
                public String setValue(String value) {
                    throw new UnsupportedOperationException();
                }
            });
        }

        return set;
    }

    @Override
    public String get(Object key) {
        for (NameValuePair pair : this.pairs)
            if (pair.getName().equals(key))
                return pair.getValue();
        return null;
    }

    @Override
    public boolean isEmpty() {
        return this.pairs.isEmpty();
    }

    @Override
    public Set<String> keySet() {
        Set<String> set = new HashSet<>();
        for (NameValuePair pair : this.pairs)
            set.add(pair.getName());
        return set;
    }

    @Override
    public String put(String key, String value) {
        ListIterator<NameValuePair> i = (ListIterator<NameValuePair>) this.pairs.listIterator();
        while (i.hasNext()) {
            NameValuePair pair = i.next();
            if (pair.getName().equals(key)) {
                i.remove();
                i.add(this.newNameValuePair(key, value));
                return pair.getValue();
            }
        }

        i.add(this.newNameValuePair(key, value));
        return null;
    }

    @Override
    public void putAll(Map<? extends String, ? extends String> m) {
        for (Entry<? extends String, ? extends String> e : m.entrySet())
            this.put(e.getKey(), e.getValue());
    }

    @Override
    public String remove(Object key) {
        ListIterator<NameValuePair> i = (ListIterator<NameValuePair>) this.pairs.listIterator();
        while (i.hasNext()) {
            NameValuePair pair = i.next();
            if (pair.getName().equals(key)) {
                i.remove();
                return pair.getValue();
            }
        }

        return null;
    }

    @Override
    public int size() {
        return this.pairs.size();
    }

    @Override
    public Collection<String> values() {
        List<String> list = new ArrayList<>(this.pairs.size());
        for (NameValuePair pair : this.pairs)
            list.add(pair.getValue());
        return list;
    }

    private T newNameValuePair(String key, String value) {
        try {
            Constructor<T> constructor = this.type.getConstructor(String.class, String.class);
            return constructor.newInstance(key, value);
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw new AlfrescoRuntimeException(e.getMessage(), e);
        }
    }

}