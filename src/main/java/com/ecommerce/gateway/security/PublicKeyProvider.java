package com.ecommerce.gateway.security;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.ecommerce.gateway.dto.PublicKeyResponse;

import reactor.core.publisher.Mono;

@Component
public class PublicKeyProvider {

    private final WebClient webClient;
    private volatile PublicKey publicKey;
    private volatile long lastFetchTime = 0;
    private static final long CACHE_DURATION_MS = 60000; // 1 minute cache

    public PublicKeyProvider(WebClient.Builder builder) {
        this.webClient = builder
                .baseUrl("http://localhost:8081")
                .build();
    }

    /**
     * Get public key reactively. Returns cached key if valid, otherwise fetches new one.
     */
    public Mono<PublicKey> getPublicKey() {
        long currentTime = System.currentTimeMillis();
        
        // Return cached key if still valid
        if (publicKey != null && (currentTime - lastFetchTime) <= CACHE_DURATION_MS) {
            return Mono.just(publicKey);
        }
        
        // Fetch new key reactively
        return fetchPublicKey()
                .doOnNext(key -> {
                    this.publicKey = key;
                    this.lastFetchTime = System.currentTimeMillis();
                });
    }

    /**
     * Force refresh the public key (useful for retry logic)
     */
    public Mono<PublicKey> refreshKey() {
        return fetchPublicKey()
                .doOnNext(key -> {
                    this.publicKey = key;
                    this.lastFetchTime = System.currentTimeMillis();
                });
    }

    /**
     * Fetch public key from auth service reactively
     */
    private Mono<PublicKey> fetchPublicKey() {
        return webClient.get()
                .uri("/auth/public-key")
                .retrieve()
                .bodyToMono(PublicKeyResponse.class)
                .map(response -> {
                    try {
                        String algorithm = response.algorithm();
                        String keyStr = response.key();
                        
                        byte[] decoded = Base64.getDecoder().decode(keyStr);
                        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
                        PublicKey key = KeyFactory
                                .getInstance(algorithm)
                                .generatePublic(spec);
                        
                        return key;
                    } catch (Exception e) {
                        throw new IllegalStateException("Failed to build public key", e);
                    }
                });
    }
}
