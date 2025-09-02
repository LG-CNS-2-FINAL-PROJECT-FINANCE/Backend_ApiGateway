package com.ddiring.k8s_api_gateway.gateway.filter;

import com.ddiring.k8s_api_gateway.security.jwt.JwtTokenValidator;
import com.ddiring.k8s_api_gateway.security.jwt.authentication.JwtAuthentication;
import com.ddiring.k8s_api_gateway.security.jwt.authentication.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class SseAuthenticationHeaderFilter implements WebFilter {

    private final JwtTokenValidator jwtTokenValidator;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        // SSE 요청만 처리
        if (path.startsWith("/api/notification/stream")) {
            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                JwtAuthentication auth = jwtTokenValidator.validateToken(token);
                UserPrincipal principal = auth != null ? auth.getPrincipal() : null;

                if (principal != null) {
                    log.info("[SSE Filter] userSeq={}, role={}", principal.getUserSeq(), principal.getRole());
                    exchange = exchange.mutate()
                            .request(r -> r.header("userSeq", principal.getUserSeq())
                                    .header("role", principal.getRole()))
                            .build();
                } else {
                    log.warn("[SSE Filter] JWT 토큰 검증 실패");
                }
            } else {
                log.warn("[SSE Filter] Authorization 헤더 없음");
            }
        }

        return chain.filter(exchange);
    }
}