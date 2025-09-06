package org.vimal.security.v3.services;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class RedisService {
    private static final Duration DEFAULT_TIME_TO_LIVE = Duration.ofMinutes(5);
    private final RedisTemplate<Object, Object> redisTemplate;

    public void save(Object key,
                     Object value) {
        save(
                key,
                value,
                DEFAULT_TIME_TO_LIVE
        );
    }

    public void save(Object key,
                     Object value,
                     Duration timeToLive) {
        redisTemplate.opsForValue()
                .set(
                        key,
                        value,
                        timeToLive
                );
    }

    public Object get(Object key) {
        return redisTemplate.opsForValue()
                .get(key);
    }

    public List<Object> getAll(Set<Object> keys) {
        return redisTemplate.opsForValue()
                .multiGet(keys);
    }

    public void delete(Object key) {
        redisTemplate.delete(key);
    }

    public void deleteAll(Set<Object> keys) {
        redisTemplate.delete(keys);
    }

    public void flushDb() {
        Objects.requireNonNull(redisTemplate.getConnectionFactory())
                .getConnection()
                .serverCommands()
                .flushDb();
    }
}
