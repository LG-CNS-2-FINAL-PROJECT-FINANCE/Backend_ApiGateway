package com.ddiring.k8s_api_gateway.security.jwt.authentication;


import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.security.Principal;
import java.util.Objects;

@Getter
@RequiredArgsConstructor
public class UserPrincipal implements Principal {
    private final String userSeq;
    private final String role;

    public boolean hasName() {
        return userSeq != null;
    }

    public boolean hasMandatory() {
        return userSeq != null;
    }

    @Override
    public String toString() {
        return getName();
    }

    @Override
    public String getName() {
        return userSeq;
    }

    @Override
    public boolean equals(Object another) {
        if (this == another) return true;
        if (another == null || getClass() != another.getClass()) return false; // 클래스 체크 방식 수정

        UserPrincipal principal = (UserPrincipal) another;

        return Objects.equals(userSeq, principal.userSeq);
    }


    @Override
    public  int hashCode() {
        int result = userSeq != null ? userSeq.hashCode() : 0;
        return result;
    }
}
