package com.security.demo.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@RequiredArgsConstructor
public class DefaultAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final OAuth2AuthorizedClientService authorizedClientService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req,
                                        HttpServletResponse res,
                                        Authentication auth) throws IOException, ServletException {
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
    }
}
