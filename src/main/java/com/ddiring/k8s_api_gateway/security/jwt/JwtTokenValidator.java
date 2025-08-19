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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


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
        String userId = null;
        Integer role = null;

        final Claims claims = this.verifyAndGetClaims(token);
        if (claims == null) {
            return null;
        }

        Date expirationDate = claims.getExpiration();
        if (expirationDate == null || expirationDate.before(new Date())) {
            return null;
        }

        userId = claims.get("userId", String.class);
        role = claims.get("role", Integer.class);

        String tokenType = claims.get("tokenType", String.class);
        if (!"access".equals(tokenType)) {
            return null;
        }

        UserPrincipal principal = new UserPrincipal(userId, role);
        String role1;
        if (role != null && role == 2) {
            role1 = "ADMIN";
        } else if (role != null && (role == 0 || role == 1)) {
            role1 = "USER";
        } else {
            role1 = "GUEST";
        }

        return new JwtAuthentication(principal, token, getGrantedAuthorities("user"));
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

    private List<GrantedAuthority> getGrantedAuthorities(String role1) {
        ArrayList<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        if (role1 != null) {
            grantedAuthorities.add(new SimpleGrantedAuthority("role1_" + role1));
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
