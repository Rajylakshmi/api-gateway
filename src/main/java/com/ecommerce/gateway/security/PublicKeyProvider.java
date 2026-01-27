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

    public PublicKeyProvider(WebClient.Builder builder) {
        this.webClient = builder
                .baseUrl("http://localhost:8081")
                .build();
    }

    public PublicKey getPublicKey() {
        if (publicKey == null) {
            synchronized (this) {
                if (publicKey == null) {
                    publicKey = fetchPublicKey();
                }
            }
        }
        return publicKey;
    }

    private PublicKey fetchPublicKey() {
        PublicKeyResponse response = webClient.get()
                .uri("/auth/public-key")
                .retrieve()
                .bodyToMono(PublicKeyResponse.class)
                .block();

        try {
            byte[] decoded = Base64.getDecoder().decode(response.getKey());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            return KeyFactory
                    .getInstance(response.getAlgorithm())
                    .generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build public key", e);
        }
    }
}
