package com.personal.secure.app.security;

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
				
				/**************************************************************************************************/
				/**									 ENABLING SECURITY HEADERS									 **/ 
				/**************************************************************************************************/
				/*Reference document: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html*/
				//Enabling basic authentication provided by Spring Boot
				.httpBasic(Customizer.withDefaults())
				.authorizeHttpRequests(auth -> auth
						//Configuring root API path for enabling the Spring Security Authentication
						.requestMatchers("/secure/*")
        				//Customizing authentication for role based user having credentials configured in application.yml
        	            .hasRole("dev")
						.anyRequest()
						.permitAll())
				//Configuring security header
				.headers(headers -> headers
						//XSS protection enabling
						.xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
						//X-Frame-Options: DENY
						.frameOptions(FrameOptionsConfig::deny)
						//Referrer-Policy: strict-origin-when-cross-origin
						.referrerPolicy(referrerPolicy -> referrerPolicy.policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
						.httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000).includeSubDomains(true).preload(true))
						.crossOriginOpenerPolicy(coop -> coop.policy(CrossOriginOpenerPolicy.SAME_ORIGIN))
						.crossOriginEmbedderPolicy(coep -> coep.policy(CrossOriginEmbedderPolicy.REQUIRE_CORP))
						.crossOriginResourcePolicy(corp -> corp.policy(CrossOriginResourcePolicy.SAME_SITE))
						.addHeaderWriter(new StaticHeadersWriter("Server","webserver"))
						.addHeaderWriter(new StaticHeadersWriter("X-DNS-Prefetch-Control","off"))
						.permissionsPolicy(permissionsPolicy -> permissionsPolicy
								.policy("geolocation=(), camera=(), microphone=(), interest-cohort=()"))
						)
				/**************************************************************************************************/
				.build();
	}
}
