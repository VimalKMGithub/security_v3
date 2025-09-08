package org.vimal.security.v3.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.vimal.security.v3.impls.UserDetailsImpl;
import org.vimal.security.v3.utils.AccessTokenUtility;

import java.io.IOException;
import java.util.Map;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

@Component
@RequiredArgsConstructor
public class AccessTokenFilter extends OncePerRequestFilter {
    private final AccessTokenUtility accessTokenUtility;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws IOException {
        try {
            String authorization = request.getHeader("Authorization");
            if (authorization != null &&
                    authorization.startsWith("Bearer ") &&
                    getContext().getAuthentication() == null) {
                UserDetailsImpl userDetails = accessTokenUtility.verifyAccessToken(authorization.substring(7));
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                getContext().setAuthentication(authentication);
            }
            filterChain.doFilter(
                    request,
                    response
            );
        } catch (Exception ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            objectMapper.writeValue(
                    response.getWriter(),
                    Map.of(
                            "error", "Unauthorized",
                            "message", ex.getMessage()
                    )
            );
        }
    }
}
