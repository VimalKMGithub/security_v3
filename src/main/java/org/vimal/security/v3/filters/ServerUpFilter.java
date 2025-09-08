package org.vimal.security.v3.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.getunleash.Unleash;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.vimal.security.v3.enums.FeatureFlags;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class ServerUpFilter extends OncePerRequestFilter {
    private final Unleash unleash;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        if (!unleash.isEnabled(FeatureFlags.SERVER_UP.name())) {
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setContentType("application/json");
            objectMapper.writeValue(
                    response.getWriter(),
                    Map.of(
                            "message", "Service Unavailable",
                            "reason", "Maintenance in progress"
                    )
            );
            return;
        }
        filterChain.doFilter(
                request,
                response
        );
    }
}
