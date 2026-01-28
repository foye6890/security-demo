package com.security.demo;

import com.security.demo.auth.DefaultAuthenticationEntryPoint;
import com.security.demo.auth.DefaultAuthenticationSuccessHandler;
import com.security.demo.auth.DefaultAuthorizationRequestRepository;
import com.security.demo.token.CookieBearerTokenResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public CookieBearerTokenResolver cookieBearerTokenResolver() {
        return new CookieBearerTokenResolver();
    }

    @Bean
    AuthenticationEntryPoint pageLoginEntryPoint() {
        return new DefaultAuthenticationEntryPoint();
    }

    @Bean
    AuthenticationSuccessHandler authenticationSuccessHandler(OAuth2AuthorizedClientService authorizedClientService) {
        return new DefaultAuthenticationSuccessHandler(authorizedClientService);
    }


    @Bean
    AuthorizationRequestRepository<OAuth2AuthorizationRequest> cookieAuthorizationRequestRepository() {
        return new DefaultAuthorizationRequestRepository();
    }

    @Bean
    @Order(1)
    SecurityFilterChain api(HttpSecurity http, CookieBearerTokenResolver bearerTokenResolver) throws Exception {
        http
            .securityMatcher("/api/**")
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
            .oauth2ResourceServer(o -> o
                .bearerTokenResolver(bearerTokenResolver)   // 你已有 CookieBearerTokenResolver
                .jwt(Customizer.withDefaults())
            );

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain web(HttpSecurity http,
                            CookieBearerTokenResolver bearerTokenResolver,
                            AuthenticationSuccessHandler authenticationSuccessHandler,
                            AuthenticationEntryPoint pageLoginEntryPoint,
                            AuthorizationRequestRepository<OAuth2AuthorizationRequest> cookieAuthorizationRequestRepository) throws Exception {
        http
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .requestCache(RequestCacheConfigurer::disable)
            .authorizeHttpRequests(a -> a
                .requestMatchers("/assets/**", "/error", "/oauth2/**", "/login/oauth2/**").permitAll()
                .anyRequest().authenticated()
            )
            // 页面也用 JWT Cookie 校验
            .oauth2ResourceServer(o -> o
                .bearerTokenResolver(bearerTokenResolver)
                .jwt(Customizer.withDefaults())
                .authenticationEntryPoint(pageLoginEntryPoint)
            )
            .oauth2Login(o -> o
                .authorizationEndpoint(ep -> ep
                    .authorizationRequestRepository(cookieAuthorizationRequestRepository) // 你已有的那个
                )
                .successHandler(authenticationSuccessHandler)
            )
            // HTML 请求未认证时用我们自定义 entry point（会写 REDIRECT_TO）
            .exceptionHandling(e -> e
                .defaultAuthenticationEntryPointFor(
                    pageLoginEntryPoint,
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            );

        return http.build();
    }
}
