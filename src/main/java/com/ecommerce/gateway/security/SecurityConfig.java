package com.ecommerce.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

public class SecurityConfig {
	
	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
	   /* return http
	        .csrf(ServerHttpSecurity.CsrfSpec::disable)
	        .authorizeExchange(exchanges -> exchanges
	            .pathMatchers(
	            		 "/auth/login",
	            		    "/auth/public-key",
	            		    "/users/validate"
	            ).permitAll()
	            .anyExchange().authenticated()
	        )
	        .build();*/
		 return http
			        .csrf(ServerHttpSecurity.CsrfSpec::disable)
			        .authorizeExchange(exchanges -> exchanges
			        	    .anyExchange().permitAll()
			        )
			        .build();
		
	}


}
