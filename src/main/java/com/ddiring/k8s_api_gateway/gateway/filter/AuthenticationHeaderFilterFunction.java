package com.ddiring.k8s_api_gateway.gateway.filter;

import com.ddiring.k8s_api_gateway.security.jwt.authentication.UserPrincipal;

import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.function.ServerRequest;

import java.util.function.Function;

@Slf4j
public class AuthenticationHeaderFilterFunction {
    public static Function<ServerRequest, ServerRequest> addHeader() {
        return request -> {
            ServerRequest.Builder requestBuilder = ServerRequest.from(request);

            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

            if( principal instanceof UserPrincipal userPrincipal) {
                String userId = userPrincipal.getUserId();
                log.info("Adding userSeq header with value: {}", userId);
                requestBuilder.header("userSeq", "46227860-da96-4412-afa2-a3fa2e0f089a");
                if (userPrincipal.getRole() != null) {
                    requestBuilder.header("role", String.valueOf(userPrincipal.getRole()));
                }
                // 다른 Claims 들도 ...
            }

            // Client ID, DeviceType 등도 필요시 입력

            return requestBuilder.build();
        };
    }
}