package com.ddiring.k8s_api_gateway.security.jwt;

import com.ddiring.k8s_api_gateway.security.jwt.authentication.JwtAuthentication;
import com.ddiring.k8s_api_gateway.security.jwt.authentication.UserPrincipal;
import com.ddiring.k8s_api_gateway.security.jwt.props.JwtConfigProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenValidator {
    private final JwtConfigProperties configProperties;

    private volatile SecretKey secretKey;

    private SecretKey getSecretKey() {
        if (secretKey == null) {
            synchronized (this) {
                if (secretKey == null) {
                    secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(configProperties.getSecretKey()));
                }
            }
        }

        return secretKey;
    }

    public JwtAuthentication validateToken(String token) {
        String userSeq = null;
        String role = null;

        final Claims claims = this.verifyAndGetClaims(token);
        if (claims == null) {
            return null;
        }

        Date expirationDate = claims.getExpiration();
        if (expirationDate == null || expirationDate.before(new Date())) {
            return null;
        }

        userSeq = claims.get("userSeq", String.class);
        role = claims.get("role", String.class);
        log.info("userSeq={}, role={}", userSeq, role);
        String tokenType = claims.get("tokenType", String.class);
        if (!"access".equals(tokenType)) {
            return null;
        }

        UserPrincipal principal = new UserPrincipal(userSeq, role);
        log.info("principal={}", principal);
        String role1;
        if (role != null && role.equals("ADMIN")) {
            role1 = "ADMIN";
        } else if (role != null && (role.equals("CREATOR") || role.equals("USER"))) {
            role1 = "USER";
        } else {
            role1 = "GUEST";
        }

        return new JwtAuthentication(principal, token, getGrantedAuthorities(role1));
    }

    private Claims verifyAndGetClaims(String token) {
        Claims claims;

        try {
            claims = Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            return null;
        }

        return claims;
    }

    private List<GrantedAuthority> getGrantedAuthorities(String role) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        if (role != null && !role.isBlank()) {
            String authority = role.startsWith("ROLE_")
                    ? role
                    : "ROLE_" + role.toUpperCase();
            grantedAuthorities.add(new SimpleGrantedAuthority(authority));
        }
        return grantedAuthorities;
    }

    public String getToken(HttpServletRequest request) {
        String authHeader = getAuthHeaderFromHeader(request);
        if (authHeader != null && authHeader.startsWith("Bearer")) {
            return authHeader.substring(7);
        }

        return null;
    }

    public String getAuthHeaderFromHeader(HttpServletRequest request) {
        return request.getHeader(configProperties.getHeader());
    }
}
