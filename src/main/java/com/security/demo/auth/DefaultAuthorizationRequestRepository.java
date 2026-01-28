package com.security.demo.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

@RequiredArgsConstructor
public class DefaultAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

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
}
