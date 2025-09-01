package org.vimal.security.v3.impls;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.stereotype.Component;
import org.vimal.security.v3.services.RedisService;

@Slf4j
@Component
@RequiredArgsConstructor
public class ApplicationShutdownListenerImpl implements ApplicationListener<ContextClosedEvent> {
    private final RedisService redisService;

    @Override
    public void onApplicationEvent(ContextClosedEvent event) {
        log.info("Application is shutting down. Flushing database in redis.");
        redisService.flushDb();
        log.info("Redis database flushed successfully.");
    }
}
