package com.ecommerce.gateway.filter;

import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * Global filter to log load balancing decisions
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class LoadBalancerLoggingFilter implements GlobalFilter, Ordered {

    private final LoadBalancerClient loadBalancerClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        URI originalUri = exchange.getRequest().getURI();
        String path = originalUri.getPath();
        
        // Extract service name from path (e.g., /payments/... -> payment-service)
        String serviceName = extractServiceName(path);
        
        if (serviceName != null) {
            try {
                // Get the actual instance that will handle the request
                ServiceInstance instance = loadBalancerClient.choose(serviceName);
                
                if (instance != null) {
                    log.info("🔀 Load Balancer Decision: Request to '{}' → Forwarding to service '{}' at {}:{}", 
                        path, 
                        serviceName, 
                        instance.getHost(), 
                        instance.getPort());
                    log.info("📍 Instance Details: instanceId={}, uri={}", 
                        instance.getInstanceId(), 
                        instance.getUri());
                } else {
                    log.warn("⚠️ No available instances found for service: {}", serviceName);
                }
            } catch (Exception e) {
                log.debug("Could not determine load balancer instance for service: {}", serviceName);
            }
        }
        
        return chain.filter(exchange);
    }

    /**
     * Extract service name from request path
     */
    private String extractServiceName(String path) {
        if (path.startsWith("/auth")) {
            return "auth-service";
        } else if (path.startsWith("/users")) {
            return "user-service";
        } else if (path.startsWith("/products")) {
            return "product-service";
        } else if (path.startsWith("/cart")) {
            return "cart-service";
        } else if (path.startsWith("/orders")) {
            return "order-service";
        } else if (path.startsWith("/payments")) {
            return "payment-service";
        }
        return null;
    }

    @Override
    public int getOrder() {
        // Run after JWT filter but before routing
        return 0;
    }
}

