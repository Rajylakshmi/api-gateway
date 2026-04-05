package com.ecommerce.gateway.security;

import java.security.PublicKey;
import java.util.List;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
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
        String method = exchange.getRequest().getMethod().toString();
        
        log.info("🌐 API Gateway received request: {} {}", method, path);

        // ✅ Bypass JWT validation for public APIs
        if (PUBLIC_PATHS.stream().anyMatch(path::equals)) {
            log.info("✅ Public path detected, bypassing JWT validation: {}", path);
            return chain.filter(exchange);
        }

        // 🔐 Validate Authorization header
        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("❌ Missing or invalid Authorization header for path: {}", path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);
        log.debug("🔍 Validating JWT token for path: {}", path);

        // Validate JWT reactively and extract user ID
        return keyProvider.getPublicKey()
                .flatMap(publicKey -> validateTokenAndExtractUserId(token, publicKey))
                .flatMap(userId -> {
                    if (userId != null) {
                        log.info("✅ JWT validation successful, userId: {}, forwarding request to: {}", userId, path);
                        // Add X-User-Id header to the request
                        ServerHttpRequest modifiedRequest = exchange.getRequest()
                                .mutate()
                                .header("X-User-Id", userId)
                                .build();
                        ServerWebExchange modifiedExchange = exchange.mutate()
                                .request(modifiedRequest)
                                .build();
                        return chain.filter(modifiedExchange);
                    } else {
                        // First validation failed, try refreshing the key
                        log.warn("⚠️ JWT validation failed, attempting key refresh for path: {}", path);
                        return keyProvider.refreshKey()
                                .flatMap(refreshedKey -> validateTokenAndExtractUserId(token, refreshedKey))
                                .flatMap(retryUserId -> {
                                    if (retryUserId != null) {
                                        log.info("✅ JWT validation successful after key refresh, userId: {}, forwarding request to: {}", retryUserId, path);
                                        // Add X-User-Id header to the request
                                        ServerHttpRequest modifiedRequest = exchange.getRequest()
                                                .mutate()
                                                .header("X-User-Id", retryUserId)
                                                .build();
                                        ServerWebExchange modifiedExchange = exchange.mutate()
                                                .request(modifiedRequest)
                                                .build();
                                        return chain.filter(modifiedExchange);
                                    } else {
                                        log.error("❌ JWT validation failed after key refresh for path: {}", path);
                                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                        return exchange.getResponse().setComplete();
                                    }
                                });
                    }
                })
                .onErrorResume(e -> {
                    log.error("❌ JWT validation error for path {}: {}", path, e.getMessage());
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }

    /**
     * Validate JWT token and extract user ID from claims
     * Returns userId if valid, null if invalid
     */
    private Mono<String> validateTokenAndExtractUserId(String token, PublicKey publicKey) {
        return Mono.fromCallable(() -> {
            try {
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(publicKey)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
                
                // Extract userId from claims
                String userId = claims.get("userId", String.class);
                
                if (userId == null || userId.isEmpty()) {
                    log.warn("⚠️ Token is valid but userId claim is missing or empty");
                    return null;
                }
                
                log.debug("✅ Token signature validation successful, userId: {}", userId);
                return userId;
            } catch (Exception e) {
                log.debug("❌ Token signature validation failed: {}", e.getMessage());
                return null;
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
