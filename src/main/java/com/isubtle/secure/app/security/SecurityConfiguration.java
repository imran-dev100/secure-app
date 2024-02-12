package com.isubtle.secure.app.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http
				
				/****************************************************************************************************************/
				/**		                       ENABLING SECURITY HEADERS	     	     			       **/ 
				/****************************************************************************************************************/
				/* Reference document: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html */
				// Enabling basic authentication provided by Spring Boot
				.httpBasic(Customizer.withDefaults())
				.authorizeHttpRequests(auth -> auth
						// Configuring root API path for enabling the Spring Security Authentication
						.requestMatchers("/secure/*")
        				// Customizing authentication for role based user having credentials configured in application.yml
        	            .hasRole("dev")
						.anyRequest()
						.permitAll())
				// Configuring security header
				.headers(headers -> headers
						// XSS protection enabling
						.xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
						// X-Frame-Options: DENY
						.frameOptions(FrameOptionsConfig::deny)
						// Referrer-Policy: strict-origin-when-cross-origin
						.referrerPolicy(referrerPolicy -> referrerPolicy.policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
						// Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
						.httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000).includeSubDomains(true).preload(true))
						// Cross-Origin-Opener-Policy: same-origin
						.crossOriginOpenerPolicy(coop -> coop.policy(CrossOriginOpenerPolicy.SAME_ORIGIN))
						// Cross-Origin-Embedder-Policy: require-corp
						.crossOriginEmbedderPolicy(coep -> coep.policy(CrossOriginEmbedderPolicy.REQUIRE_CORP))
						// Cross-Origin-Resource-Policy: same-site
						.crossOriginResourcePolicy(corp -> corp.policy(CrossOriginResourcePolicy.SAME_SITE))
						// Server: webserver
						.addHeaderWriter(new StaticHeadersWriter("Server", "webserver"))
						// X-DNS-Prefetch-Control: off
						.addHeaderWriter(new StaticHeadersWriter("X-DNS-Prefetch-Control", "off"))
						// Permissions-Policy: geolocation=(), camera=(), microphone=()
						// Permissions-Policy: interest-cohort=()
						.permissionsPolicy(permissionsPolicy -> permissionsPolicy
								.policy("geolocation=(), camera=(), microphone=(), interest-cohort=()"))
						)
				/****************************************************************************************************************/
				.build();
	}
}
