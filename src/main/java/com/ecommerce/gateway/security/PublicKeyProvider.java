package com.ecommerce.gateway.security;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.ecommerce.gateway.dto.PublicKeyResponse;

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

    public PublicKey getPublicKey() {
        long currentTime = System.currentTimeMillis();
        
        // Refresh if cache expired or key is null
        if (publicKey == null || (currentTime - lastFetchTime) > CACHE_DURATION_MS) {
            synchronized (this) {
                if (publicKey == null || (currentTime - lastFetchTime) > CACHE_DURATION_MS) {
                    publicKey = fetchPublicKey();
                    lastFetchTime = currentTime;
                }
            }
        }
        return publicKey;
    }

    private PublicKey fetchPublicKey() {
        try {
            PublicKeyResponse response = webClient.get()
                    .uri("/auth/public-key")
                    .retrieve()
                    .bodyToMono(PublicKeyResponse.class)
                    .block();

            byte[] decoded = Base64.getDecoder().decode(response.getKey());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            return KeyFactory
                    .getInstance(response.getAlgorithm())
                    .generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build public key", e);
        }
    }
    
    // Method to force refresh (useful for testing or manual refresh)
    public void refreshKey() {
        synchronized (this) {
            publicKey = fetchPublicKey();
            lastFetchTime = System.currentTimeMillis();
        }
    }
}
