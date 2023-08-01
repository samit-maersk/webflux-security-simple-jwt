package com.example.webfluxsecurityresourceserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

@SpringBootApplication
public class WebfluxSecurityResourceserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(WebfluxSecurityResourceserverApplication.class, args);
	}

	@Bean
	RouterFunction routerFunction() {
		return RouterFunctions
				.route()
				.GET("/greet", request -> {
					return ServerResponse.ok().bodyValue(new Message("Hello World"));
				})
				.build();
	}

}
record Message(String message){}

@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
class SecurityConfiguration {
	@Bean
	SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
		http.csrf(csrfSpec -> csrfSpec.disable())
				.authorizeExchange((authorize) -> authorize
						.anyExchange().authenticated()
				)
				.oauth2ResourceServer(oauth2ResourceServer ->
						oauth2ResourceServer.jwt(Customizer.withDefaults()));
		return http.build();
	}

	private ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter() {
		var jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
		var jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
		return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
	}
}