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
                String userSeq = userPrincipal.getUserSeq();
                String role =  userPrincipal.getRole();
                requestBuilder.header("userSeq", userSeq);
                requestBuilder.header("role", role);
            }


            return requestBuilder.build();
        };
    }
}