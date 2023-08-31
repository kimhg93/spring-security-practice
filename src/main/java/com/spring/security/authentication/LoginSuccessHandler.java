package com.spring.security.authentication;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        List<GrantedAuthority> authorities = (List<GrantedAuthority>) authentication.getAuthorities();

        System.err.println(authorities.toString());

        boolean loginCheck = authorities.stream()
                .anyMatch(role -> "ROLE_PRE_AUTH_USER".equalsIgnoreCase(role.toString()));

        System.err.println(loginCheck);
        if(loginCheck) response.setStatus(203);
        else {
            SecurityContextHolder.clearContext();
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
        }

    }
}
