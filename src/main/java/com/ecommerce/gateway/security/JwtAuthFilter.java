package com.ecommerce.gateway.security;

import java.security.PublicKey;
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

        // Validate JWT reactively
        return keyProvider.getPublicKey()
                .flatMap(publicKey -> validateToken(token, publicKey))
                .flatMap(isValid -> {
                    if (isValid) {
                        return chain.filter(exchange);
                    } else {
                        // First validation failed, try refreshing the key
                        return keyProvider.refreshKey()
                                .flatMap(refreshedKey -> validateToken(token, refreshedKey))
                                .flatMap(retryValid -> {
                                    if (retryValid) {
                                        return chain.filter(exchange);
                                    } else {
                                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                        return exchange.getResponse().setComplete();
                                    }
                                });
                    }
                })
                .onErrorResume(e -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }

    /**
     * Validate JWT token with given public key
     */
    private Mono<Boolean> validateToken(String token, PublicKey publicKey) {
        return Mono.fromCallable(() -> {
            try {
                Jwts.parserBuilder()
                        .setSigningKey(publicKey)
                        .build()
                        .parseClaimsJws(token);
                return true;
            } catch (Exception e) {
                return false;
            }
        });
    }

    /**
     * Run before Spring Security
     */
    @Override
    public int getOrder() {
        return -1;
    }
}
