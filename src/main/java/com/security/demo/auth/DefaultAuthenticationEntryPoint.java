package com.security.demo.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

@RequiredArgsConstructor
public class DefaultAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        // ① 清掉过期/无效 JWT Cookie，避免后续请求一直带着坏 token
        ResponseCookie clearJwt = ResponseCookie.from("AUTH_TOKEN", "")
            .httpOnly(true)
            .secure(false)        // 本地 false；上线 https 要 true
            .sameSite("Lax")
            .path("/")
            .maxAge(0)
            .build();
        response.addHeader("Set-Cookie", clearJwt.toString());

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
    }
}
