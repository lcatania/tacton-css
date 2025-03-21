/*
 * The MIT License
 *
 * Copyright 2020 Tacton Systems AB
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.tacton.config;

import com.tacton.services.UserSecurityService;

import jakarta.servlet.DispatcherType;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity(debug = false)
// @EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

	@Autowired
	BCryptPasswordEncoder encoder;

	@Autowired
	UserSecurityService userSecurityService;

	// Allowed for all
	private static final String[] PublicMatchers = {
			"/webjars/**",
			"/css/**",
			"/js/**",
			"/img/**",
			"/fonts/**",
			"/webfonts/**",
			"/products/**",
			"/images/**",
			"/",
			"/configurator",
			"/configure",
			"/configure-needs/**",
			"/templates",
			"/vis/**",
			"/shop",
			"/shop/**",
			"/admin-assets/**",
			"/accessDenied"

	};

	// only allowed for non-authenticated
	private static final String[] AnonymousMatchers = {
			"/login",
			"/login/**",
			"/logout",
			"/logout/**",
			"/register",
	};

	// only allowed for users with admin role
	private static final String[] AdminMatchers = {
			"/admin",
			"/admin/**",
	};

	@Bean
	public AuthenticationSuccessHandler successHandler() {
		return new CustomLoginSuccessHandler();
	}

	@Bean
	public AuthenticationFailureHandler failureHandler() {
		return new CustomAuthenticationFailureHandler();
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		return new CustomAccessDeniedHandler();
	}

	
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
	    requestCache.setMatchingRequestParameterName(null);
	    
		http
				.cors(cors -> cors.disable())
				.authorizeHttpRequests(auth -> auth
						.requestMatchers(AdminMatchers).hasRole("ADMIN")
						.requestMatchers(PublicMatchers).permitAll()
						.requestMatchers(AnonymousMatchers).anonymous()
						.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
						.anyRequest().authenticated())
				.exceptionHandling(exception -> exception.accessDeniedHandler(accessDeniedHandler()))
				.formLogin(login -> login
						.loginPage("/login")
						.successHandler(successHandler())
						.failureHandler(failureHandler())
						.failureUrl("/login/error")
						.permitAll())
				.logout(logout -> logout
						.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
						.logoutSuccessUrl("/logout/success")
						.invalidateHttpSession(true)
						.deleteCookies("remember-me")
						.permitAll())
				.rememberMe(rememberMe -> {
				})
				.requestCache((cache) -> cache
			            .requestCache(requestCache)
			        );
	         

		http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));
		return http.build();
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return web -> web.debug(false)
				.ignoring()
				.requestMatchers("/h2/**");
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth
				.userDetailsService(userSecurityService)
				.passwordEncoder(encoder);
	}

}
