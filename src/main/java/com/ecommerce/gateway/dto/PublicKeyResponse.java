package com.ecommerce.gateway.dto;
import lombok.Data;

@Data
public class PublicKeyResponse {
    private String algorithm;
    private String key;
}