/*
 * Copyright (c) 2002, 2011, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package sun.security.util;

import java.util.*;
import java.lang.ref.*;

/**
 * Abstract base class and factory for caches. A cache is a key-value mapping.
 * It has properties that make it more suitable for caching than a Map.
 *
 * The factory methods can be used to obtain two different implementations.
 * They have the following properties:
 *
 *  . keys and values reside in memory
 *
 *  . keys and values must be non-null
 *
 *  . maximum size. Replacements are made in LRU order.
 *
 *  . optional lifetime, specified in seconds.
 *
 *  . safe for concurrent use by multiple threads
 *
 *  . values are held by either standard references or via SoftReferences.
 *    SoftReferences have the advantage that they are automatically cleared
 *    by the garbage collector in response to memory demand. This makes it
 *    possible to simple set the maximum size to a very large value and let
 *    the GC automatically size the cache dynamically depending on the
 *    amount of available memory.
 *
 * However, note that because of the way SoftReferences are implemented in
 * HotSpot at the moment, this may not work perfectly as it clears them fairly
 * eagerly. Performance may be improved if the Java heap size is set to larger
 * value using e.g. java -ms64M -mx128M foo.Test
 *
 * Cache sizing: the memory cache is implemented on top of a LinkedHashMap.
 * In its current implementation, the number of buckets (NOT entries) in
 * (Linked)HashMaps is always a power of two. It is recommended to set the
 * maximum cache size to value that uses those buckets fully. For example,
 * if a cache with somewhere between 500 and 1000 entries is desired, a
 * maximum size of 750 would be a good choice: try 1024 buckets, with a
 * load factor of 0.75f, the number of entries can be calculated as
 * buckets / 4 * 3. As mentioned above, with a SoftReference cache, it is
 * generally reasonable to set the size to a fairly large value.
 *
 * @author Andreas Sterbenz
 */
public abstract class Cache<K,V> {

    protected Cache() {
        // empty
    }

    /**
     * Return the number of currently valid entries in the cache.
     */
    public abstract int size();

    /**
     * Remove all entries from the cache.
     */
    public abstract void clear();

    /**
     * Add an entry to the cache.
     */
    public abstract void put(K key, V value);

    /**
     * Get a value from the cache.
     */
    public abstract V get(Object key);

    /**
     * Remove an entry from the cache.
     */
    public abstract void remove(Object key);

    /**
     * Set the maximum size.
     */
    public abstract void setCapacity(int size);

    /**
     * Set the timeout(in seconds).
     */
    public abstract void setTimeout(int timeout);

    /**
     * accept a visitor
     */
    public abstract void accept(CacheVisitor<K,V> visitor);

    /**
     * Return a new memory cache with the specified maximum size, unlimited
     * lifetime for entries, with the values held by SoftReferences.
     */
    public static <K,V> Cache<K,V> newSoftMemoryCache(final int size) {
        return new MemoryCache<>(true, size);
    }

    /**
     * Return a new memory cache with the specified maximum size, the
     * specified maximum lifetime (in seconds), with the values held
     * by SoftReferences.
     */
    public static <K,V> Cache<K,V> newSoftMemoryCache(final int size, final int timeout) {
        return new MemoryCache<>(true, size, timeout);
    }

    /**
     * Return a new memory cache with the specified maximum size, unlimited
     * lifetime for entries, with the values held by standard references.
     */
    public static <K,V> Cache<K,V> newHardMemoryCache(final int size) {
        return new MemoryCache<>(false, size);
    }

    /**
     * Return a dummy cache that does nothing.
     */
    @SuppressWarnings("unchecked")
    public static <K,V> Cache<K,V> newNullCache() {
        return (Cache<K,V>) NullCache.INSTANCE;
    }

    /**
     * Return a new memory cache with the specified maximum size, the
     * specified maximum lifetime (in seconds), with the values held
     * by standard references.
     */
    public static <K,V> Cache<K,V> newHardMemoryCache(final int size, final int timeout) {
        return new MemoryCache<>(false, size, timeout);
    }

    /**
     * Utility class that wraps a byte array and implements the equals()
     * and hashCode() contract in a way suitable for Maps and caches.
     */
    public static class EqualByteArray {

        private final byte[] b;
        private volatile int hash;

        public EqualByteArray(final byte[] b) {
            this.b = b;
        }

        @Override
        public int hashCode() {
            int h = hash;
            if (h == 0) {
                h = b.length + 1;
                for (int i = 0; i < b.length; i++) {
                    h += (b[i] & 0xff) * 37;
                }
                hash = h;
            }
            return h;
        }

        @Override
        public boolean equals(final Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof EqualByteArray == false) {
                return false;
            }
            final EqualByteArray other = (EqualByteArray)obj;
            return Arrays.equals(b, other.b);
        }
    }

    public interface CacheVisitor<K,V> {
        public void visit(Map<K,V> map);
    }

}

class NullCache<K,V> extends Cache<K,V> {

    static final Cache<Object,Object> INSTANCE = new NullCache<>();

    private NullCache() {
        // empty
    }

    @Override
    public int size() {
        return 0;
    }

    @Override
    public void clear() {
        // empty
    }

    @Override
    public void put(final K key, final V value) {
        // empty
    }

    @Override
    public V get(final Object key) {
        return null;
    }

    @Override
    public void remove(final Object key) {
        // empty
    }

    @Override
    public void setCapacity(final int size) {
        // empty
    }

    @Override
    public void setTimeout(final int timeout) {
        // empty
    }

    @Override
    public void accept(final CacheVisitor<K,V> visitor) {
        // empty
    }

}

class MemoryCache<K,V> extends Cache<K,V> {

    private static final float LOAD_FACTOR = 0.75f;

    // XXXX
    private static final boolean DEBUG = false;

    private final Map<K, CacheEntry<K,V>> cacheMap;
    private int maxSize;
    private long lifetime;

    // ReferenceQueue is of type V instead of Cache<K,V>
    // to allow SoftCacheEntry to extend SoftReference<V>
    private final ReferenceQueue<V> queue;

    public MemoryCache(final boolean soft, final int maxSize) {
        this(soft, maxSize, 0);
    }

    public MemoryCache(final boolean soft, final int maxSize, final int lifetime) {
        this.maxSize = maxSize;
        this.lifetime = lifetime * 1000;
        if (soft)
            this.queue = new ReferenceQueue<>();
        else
            this.queue = null;

        final int buckets = (int)(maxSize / LOAD_FACTOR) + 1;
        cacheMap = new LinkedHashMap<>(buckets, LOAD_FACTOR, true);
    }

    /**
     * Empty the reference queue and remove all corresponding entries
     * from the cache.
     *
     * This method should be called at the beginning of each public
     * method.
     */
    private void emptyQueue() {
        if (queue == null) {
            return;
        }
        final int startSize = cacheMap.size();
        while (true) {
            @SuppressWarnings("unchecked")
            final
            CacheEntry<K,V> entry = (CacheEntry<K,V>)queue.poll();
            if (entry == null) {
                break;
            }
            final K key = entry.getKey();
            if (key == null) {
                // key is null, entry has already been removed
                continue;
            }
            final CacheEntry<K,V> currentEntry = cacheMap.remove(key);
            // check if the entry in the map corresponds to the expired
            // entry. If not, readd the entry
            if ((currentEntry != null) && (entry != currentEntry)) {
                cacheMap.put(key, currentEntry);
            }
        }
        if (DEBUG) {
            final int endSize = cacheMap.size();
            if (startSize != endSize) {
                System.out.println("*** Expunged " + (startSize - endSize)
                        + " entries, " + endSize + " entries left");
            }
        }
    }

    /**
     * Scan all entries and remove all expired ones.
     */
    private void expungeExpiredEntries() {
        emptyQueue();
        if (lifetime == 0) {
            return;
        }
        int cnt = 0;
        final long time = System.currentTimeMillis();
        for (final Iterator<CacheEntry<K,V>> t = cacheMap.values().iterator();
                t.hasNext(); ) {
            final CacheEntry<K,V> entry = t.next();
            if (entry.isValid(time) == false) {
                t.remove();
                cnt++;
            }
        }
        if (DEBUG) {
            if (cnt != 0) {
                System.out.println("Removed " + cnt
                        + " expired entries, remaining " + cacheMap.size());
            }
        }
    }

    @Override
    public synchronized int size() {
        expungeExpiredEntries();
        return cacheMap.size();
    }

    @Override
    public synchronized void clear() {
        if (queue != null) {
            // if this is a SoftReference cache, first invalidate() all
            // entries so that GC does not have to enqueue them
            for (final CacheEntry<K,V> entry : cacheMap.values()) {
                entry.invalidate();
            }
            while (queue.poll() != null) {
                // empty
            }
        }
        cacheMap.clear();
    }

    @Override
    public synchronized void put(final K key, final V value) {
        emptyQueue();
        final long expirationTime = (lifetime == 0) ? 0 :
                                        System.currentTimeMillis() + lifetime;
        final CacheEntry<K,V> newEntry = newEntry(key, value, expirationTime, queue);
        final CacheEntry<K,V> oldEntry = cacheMap.put(key, newEntry);
        if (oldEntry != null) {
            oldEntry.invalidate();
            return;
        }
        if (maxSize > 0 && cacheMap.size() > maxSize) {
            expungeExpiredEntries();
            if (cacheMap.size() > maxSize) { // still too large?
                final Iterator<CacheEntry<K,V>> t = cacheMap.values().iterator();
                final CacheEntry<K,V> lruEntry = t.next();
                if (DEBUG) {
                    System.out.println("** Overflow removal "
                        + lruEntry.getKey() + " | " + lruEntry.getValue());
                }
                t.remove();
                lruEntry.invalidate();
            }
        }
    }

    @Override
    public synchronized V get(final Object key) {
        emptyQueue();
        final CacheEntry<K,V> entry = cacheMap.get(key);
        if (entry == null) {
            return null;
        }
        final long time = (lifetime == 0) ? 0 : System.currentTimeMillis();
        if (entry.isValid(time) == false) {
            if (DEBUG) {
                System.out.println("Ignoring expired entry");
            }
            cacheMap.remove(key);
            return null;
        }
        return entry.getValue();
    }

    @Override
    public synchronized void remove(final Object key) {
        emptyQueue();
        final CacheEntry<K,V> entry = cacheMap.remove(key);
        if (entry != null) {
            entry.invalidate();
        }
    }

    @Override
    public synchronized void setCapacity(final int size) {
        expungeExpiredEntries();
        if (size > 0 && cacheMap.size() > size) {
            final Iterator<CacheEntry<K,V>> t = cacheMap.values().iterator();
            for (int i = cacheMap.size() - size; i > 0; i--) {
                final CacheEntry<K,V> lruEntry = t.next();
                if (DEBUG) {
                    System.out.println("** capacity reset removal "
                        + lruEntry.getKey() + " | " + lruEntry.getValue());
                }
                t.remove();
                lruEntry.invalidate();
            }
        }

        maxSize = size > 0 ? size : 0;

        if (DEBUG) {
            System.out.println("** capacity reset to " + size);
        }
    }

    @Override
    public synchronized void setTimeout(final int timeout) {
        emptyQueue();
        lifetime = timeout > 0 ? timeout * 1000L : 0L;

        if (DEBUG) {
            System.out.println("** lifetime reset to " + timeout);
        }
    }

    // it is a heavyweight method.
    @Override
    public synchronized void accept(final CacheVisitor<K,V> visitor) {
        expungeExpiredEntries();
        final Map<K,V> cached = getCachedEntries();

        visitor.visit(cached);
    }

    private Map<K,V> getCachedEntries() {
        final Map<K,V> kvmap = new HashMap<>(cacheMap.size());

        for (final CacheEntry<K,V> entry : cacheMap.values()) {
            kvmap.put(entry.getKey(), entry.getValue());
        }

        return kvmap;
    }

    protected CacheEntry<K,V> newEntry(final K key, final V value,
            final long expirationTime, final ReferenceQueue<V> queue) {
        if (queue != null) {
            return new SoftCacheEntry<>(key, value, expirationTime, queue);
        } else {
            return new HardCacheEntry<>(key, value, expirationTime);
        }
    }

    private static interface CacheEntry<K,V> {

        boolean isValid(long currentTime);

        void invalidate();

        K getKey();

        V getValue();

    }

    private static class HardCacheEntry<K,V> implements CacheEntry<K,V> {

        private K key;
        private V value;
        private long expirationTime;

        HardCacheEntry(final K key, final V value, final long expirationTime) {
            this.key = key;
            this.value = value;
            this.expirationTime = expirationTime;
        }

        @Override
        public K getKey() {
            return key;
        }

        @Override
        public V getValue() {
            return value;
        }

        @Override
        public boolean isValid(final long currentTime) {
            final boolean valid = (currentTime <= expirationTime);
            if (valid == false) {
                invalidate();
            }
            return valid;
        }

        @Override
        public void invalidate() {
            key = null;
            value = null;
            expirationTime = -1;
        }
    }

    private static class SoftCacheEntry<K,V>
            extends SoftReference<V>
            implements CacheEntry<K,V> {

        private K key;
        private long expirationTime;

        SoftCacheEntry(final K key, final V value, final long expirationTime,
                final ReferenceQueue<V> queue) {
            super(value, queue);
            this.key = key;
            this.expirationTime = expirationTime;
        }

        @Override
        public K getKey() {
            return key;
        }

        @Override
        public V getValue() {
            return get();
        }

        @Override
        public boolean isValid(final long currentTime) {
            final boolean valid = (currentTime <= expirationTime) && (get() != null);
            if (valid == false) {
                invalidate();
            }
            return valid;
        }

        @Override
        public void invalidate() {
            clear();
            key = null;
            expirationTime = -1;
        }
    }

}
