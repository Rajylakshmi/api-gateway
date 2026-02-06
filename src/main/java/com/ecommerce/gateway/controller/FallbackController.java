package com.ecommerce.gateway.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Fallback Controller for Circuit Breaker
 * Provides fallback responses when services are unavailable
 */
@RestController
@RequestMapping("/fallback")
public class FallbackController {

    @GetMapping("/auth")
    public ResponseEntity<Map<String, String>> authFallback() {
        return createFallbackResponse("Auth Service is currently unavailable. Please try again later.");
    }

    @GetMapping("/users")
    public ResponseEntity<Map<String, String>> usersFallback() {
        return createFallbackResponse("User Service is currently unavailable. Please try again later.");
    }

    @GetMapping("/products")
    public ResponseEntity<Map<String, String>> productsFallback() {
        return createFallbackResponse("Product Service is currently unavailable. Please try again later.");
    }

    @GetMapping("/cart")
    public ResponseEntity<Map<String, String>> cartFallback() {
        return createFallbackResponse("Cart Service is currently unavailable. Please try again later.");
    }

    @GetMapping("/orders")
    public ResponseEntity<Map<String, String>> ordersFallback() {
        return createFallbackResponse("Order Service is currently unavailable. Please try again later.");
    }

    @GetMapping("/payments")
    public ResponseEntity<Map<String, String>> paymentsFallback() {
        return createFallbackResponse("Payment Service is currently unavailable. Please try again later.");
    }

    private ResponseEntity<Map<String, String>> createFallbackResponse(String message) {
        Map<String, String> response = new HashMap<>();
        response.put("error", "Service Unavailable");
        response.put("message", message);
        response.put("status", String.valueOf(HttpStatus.SERVICE_UNAVAILABLE.value()));
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
}