package com.ecommerce.gateway.security;

import java.util.List;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Jwts;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private final PublicKeyProvider keyProvider;

    public JwtAuthFilter(PublicKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    /**
     * Public APIs that DO NOT require JWT
     */
    private static final List<String> PUBLIC_PATHS = List.of(
            "/auth/login",
            "/auth/register",
            "/auth/public-key",
            "/users/validate"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();

        // ✅ Bypass JWT validation for public APIs
        if (PUBLIC_PATHS.stream().anyMatch(path::equals)) {
            return chain.filter(exchange);
        }

        // 🔐 Validate Authorization header
        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        try {
            // First attempt with cached key
            Jwts.parserBuilder()
                    .setSigningKey(keyProvider.getPublicKey())
                    .build()
                    .parseClaimsJws(token);
        } catch (Exception ex) {
            // Retry once with refreshed key (in case auth-service restarted)
            try {
                keyProvider.refreshKey();
                Jwts.parserBuilder()
                        .setSigningKey(keyProvider.getPublicKey())
                        .build()
                        .parseClaimsJws(token);
            } catch (Exception retryEx) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        }

        return chain.filter(exchange);
    }

    /**
     * Run before Spring Security
     */
    @Override
    public int getOrder() {
        return -1;
    }
}
