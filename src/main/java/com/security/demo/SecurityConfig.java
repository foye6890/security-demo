package com.security.demo;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.security.demo.token.CookieBearerTokenResolver;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
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
        return (request, response, authException) -> {
            // 只针对浏览器页面请求：保存原始URL
            String uri = request.getRequestURI();
            String qs = request.getQueryString();
            String full = (qs == null ? uri : uri + "?" + qs);

            String encoded = Base64.getUrlEncoder().encodeToString(full.getBytes(StandardCharsets.UTF_8));
            ResponseCookie c = ResponseCookie.from("REDIRECT_TO", encoded)
                .httpOnly(true)
                .secure(false)      // 本地 false；上 https 必须 true
                .sameSite("Lax")
                .path("/")
                .maxAge(Duration.ofMinutes(5))
                .build();
            response.addHeader("Set-Cookie", c.toString());

            // 再跳到 OAuth2 授权入口
            response.sendRedirect("/oauth2/authorization/keycloak");
        };
    }

    @Bean
    @Order(1)
    SecurityFilterChain api(HttpSecurity http, CookieBearerTokenResolver bearerTokenResolver) throws Exception {
        http
            .securityMatcher("/api/**")
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable())
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
                            BearerTokenResolver bearerTokenResolver,
                            OAuth2AuthorizedClientService authorizedClientService) throws Exception {
        http
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a
                .requestMatchers("/assets/**", "/error", "/oauth2/**", "/login/oauth2/**").permitAll()
                .anyRequest().authenticated()
            )
            // 页面也用 JWT Cookie 校验
            .oauth2ResourceServer(o -> o
                .bearerTokenResolver(bearerTokenResolver)
                .jwt(Customizer.withDefaults())
            )
            .oauth2Login(o -> o
                .authorizationEndpoint(ep -> ep
                    .authorizationRequestRepository(cookieAuthorizationRequestRepository()) // 你已有的那个
                )
                .successHandler((req, res, auth) -> {
                    // ① 写入 AUTH_TOKEN Cookie
                    OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) auth;
                    OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                        token.getAuthorizedClientRegistrationId(), token.getName());
                    String accessToken = client.getAccessToken().getTokenValue();

                    ResponseCookie jwtCookie = ResponseCookie.from("AUTH_TOKEN", accessToken)
                        .httpOnly(true)
                        .secure(false)
                        .sameSite("Lax")
                        .path("/")
                        .build();
                    res.addHeader("Set-Cookie", jwtCookie.toString());

                    // ② 读取 REDIRECT_TO 并回跳
                    String target = "/";
                    Cookie[] cookies = req.getCookies();
                    if (cookies != null) {
                        for (Cookie c : cookies) {
                            if ("REDIRECT_TO".equals(c.getName()) && c.getValue() != null && !c.getValue().isBlank()) {
                                try {
                                    target = new String(Base64.getUrlDecoder().decode(c.getValue()), StandardCharsets.UTF_8);
                                } catch (IllegalArgumentException ignored) { }
                                break;
                            }
                        }
                    }

                    // 清理 REDIRECT_TO cookie
                    ResponseCookie clear = ResponseCookie.from("REDIRECT_TO", "")
                        .httpOnly(true)
                        .secure(false)
                        .sameSite("Lax")
                        .path("/")
                        .maxAge(0)
                        .build();
                    res.addHeader("Set-Cookie", clear.toString());

                    res.sendRedirect(target);
                })
            )
            // ✅ 关键：HTML 请求未认证时用我们自定义 entry point（会写 REDIRECT_TO）
            .exceptionHandling(e -> e
                .defaultAuthenticationEntryPointFor(
                    pageLoginEntryPoint(),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            );

        return http.build();
    }

    @Bean
    AuthorizationRequestRepository<OAuth2AuthorizationRequest> cookieAuthorizationRequestRepository() {
        return new AuthorizationRequestRepository<>() {

            private final String COOKIE_NAME = "OAUTH2_AUTHZ_REQ";

            @Override
            public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
                Cookie[] cookies = request.getCookies();
                if (cookies == null) return null;
                for (Cookie c : cookies) {
                    if (COOKIE_NAME.equals(c.getName()) && c.getValue() != null && !c.getValue().isBlank()) {
                        return deserialize(c.getValue());
                    }
                }
                return null;
            }

            @Override
            public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
                                                 HttpServletRequest request,
                                                 HttpServletResponse response) {
                if (authorizationRequest == null) {
                    // remove
                    ResponseCookie rc = ResponseCookie.from(COOKIE_NAME, "")
                        .httpOnly(true).secure(false).sameSite("Lax").path("/").maxAge(0).build();
                    response.addHeader("Set-Cookie", rc.toString());
                    return;
                }

                String value = serialize(authorizationRequest);
                ResponseCookie rc = ResponseCookie.from(COOKIE_NAME, value)
                    .httpOnly(true)
                    .secure(false)
                    .sameSite("Lax")
                    .path("/")
                    .maxAge(Duration.ofMinutes(5)) // 授权流程短期有效
                    .build();
                response.addHeader("Set-Cookie", rc.toString());
            }

            @Override
            public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                         HttpServletResponse response) {
                OAuth2AuthorizationRequest existing = loadAuthorizationRequest(request);
                ResponseCookie rc = ResponseCookie.from(COOKIE_NAME, "")
                    .httpOnly(true).secure(false).sameSite("Lax").path("/").maxAge(0).build();
                response.addHeader("Set-Cookie", rc.toString());
                return existing;
            }

            private String serialize(OAuth2AuthorizationRequest req) {
                try {
                    byte[] bytes = org.springframework.util.SerializationUtils.serialize(req);
                    return java.util.Base64.getUrlEncoder().encodeToString(bytes);
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to serialize OAuth2AuthorizationRequest", e);
                }
            }

            private OAuth2AuthorizationRequest deserialize(String value) {
                try {
                    byte[] bytes = java.util.Base64.getUrlDecoder().decode(value);
                    Object obj = org.springframework.util.SerializationUtils.deserialize(bytes);
                    return (OAuth2AuthorizationRequest) obj;
                } catch (Exception e) {
                    return null; // 解析失败视为无状态，触发重新登录
                }
            }
        };
    }
//
//    @Bean
//    @Order(2)
//    public SecurityFilterChain appServerSecurityFilterChain(HttpSecurity http, CookieBearerTokenResolver bearerTokenResolver) throws Exception {
//        http
//            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//            .authorizeHttpRequests(auth -> auth
//                .requestMatchers("/login", "/assets/**").permitAll()
//                .anyRequest().authenticated()
//            )
//            .oauth2ResourceServer(o -> o
//                .bearerTokenResolver(bearerTokenResolver)
//                .jwt(Customizer.withDefaults())
//            );
//
//        return http.build();
//    }
//
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails =
//            User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }
//
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient oidcClient =
//            RegisteredClient.withId(UUID.randomUUID().toString()).clientId("oidc-client").clientSecret("{noop}secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
//                .postLogoutRedirectUri("http://127.0.0.1:8080/").scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();
//
//        return new InMemoryRegisteredClientRepository(oidcClient);
//    }
//
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        RSAKey rsaKey =
//            new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return new ImmutableJWKSet<>(jwkSet);
//    }
//
//    private static KeyPair generateRsaKey() {
//        KeyPair keyPair;
//        try {
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//            keyPairGenerator.initialize(2048);
//            keyPair = keyPairGenerator.generateKeyPair();
//        } catch (Exception ex) {
//            throw new IllegalStateException(ex);
//        }
//        return keyPair;
//    }
//
//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().build();
//    }
}
