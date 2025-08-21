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
                String role =  userPrincipal.getRole();
                log.info("Adding userSeq header with value: {}", userId);
                requestBuilder.header("userSeq", userPrincipal.getUserId());
                requestBuilder.header("role", String.valueOf(userPrincipal.getRole()));
            }


            return requestBuilder.build();
        };
    }
}