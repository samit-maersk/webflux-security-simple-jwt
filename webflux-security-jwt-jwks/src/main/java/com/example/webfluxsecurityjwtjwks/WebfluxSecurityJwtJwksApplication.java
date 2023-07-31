package com.example.webfluxsecurityjwtjwks;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.stream.Collectors;

@SpringBootApplication
@RequiredArgsConstructor
public class WebfluxSecurityJwtJwksApplication {
	final JwtEncoder encoder;
	private final JWKSet jwkSet;

	public static void main(String[] args) {
		SpringApplication.run(WebfluxSecurityJwtJwksApplication.class, args);
	}

	@Bean
	RouterFunction routerFunction() {
		return RouterFunctions
				.route()
				.POST("/register",request -> ServerResponse.noContent().build())
				.GET("/jwks", request -> {
					return ServerResponse.ok().bodyValue(jwkSet.toJSONObject());
				})
				.build();
	}
}

@RestController
@RequiredArgsConstructor
class ApplicationRouter {
	final JwtEncoder encoder;
	@PostMapping("/login")
	public Mono<TokenResponse> login(Authentication authentication) {
		Instant now = Instant.now();
		long expiry = 36000L;
		String scope = authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(" "));
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer("self")
				.issuedAt(now)
				.expiresAt(now.plusSeconds(expiry))
				.subject(authentication.getName())
				.claim("scope", scope)
				.build();
		var e = encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
		return Mono.just(new TokenResponse(e));
	}
}

record TokenResponse(String token){}

@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
class SecurityConfig {

	@Bean
	JwtEncoder jwtEncoder() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		JWK jwk = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
		return new NimbusJwtEncoder(jwks);
	}


	@Bean
	SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
		return
				http
						.authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
								.pathMatchers("/jwks","/register")
								.permitAll()
								.anyExchange()
								.authenticated())
						.csrf(csrfSpec -> csrfSpec.disable())
						.httpBasic(Customizer.withDefaults())
						//This will enable a login screen
						//.formLogin(Customizer.withDefaults())
						.build();
	}

	@Bean
	public JWKSet jwkSet() {
		KeyPair keyPair = generateRsaKey();
		RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.RS256)
				.keyID("bael-key-id");
		return new JWKSet(builder.build());
	}

	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}
}