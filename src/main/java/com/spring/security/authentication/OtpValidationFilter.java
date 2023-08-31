package com.spring.security.authentication;

import com.spring.security.domain.FormMember;
import com.spring.security.domain.Member;
import com.spring.security.domain.OAuthMember;
import com.spring.security.persistence.FormMemberRepository;
import com.spring.security.persistence.OAuthMemberRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.parameters.P;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.List;
import java.util.Optional;


@RequiredArgsConstructor
public class OtpValidationFilter extends OncePerRequestFilter {

    private final FormMemberRepository formMemberRepository;
    private final OAuthMemberRepository oAuthMemberRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.err.println(authentication.toString());
        List<GrantedAuthority> roles = (List<GrantedAuthority>) authentication.getAuthorities();

        boolean logon = roles.stream()
                .anyMatch(r -> "ROLE_PRE_AUTH_USER".equalsIgnoreCase(r.toString()));

        if(logon && "/otp/valid".equals(request.getRequestURI()) && "GET".equalsIgnoreCase(request.getMethod())) {

            String pass = request.getParameter("pass");
            int code = Integer.parseInt(pass);
            GoogleAuthenticator gAuth = new GoogleAuthenticator();
            boolean isCodeValid = gAuth.authorize("V2Z4PW46MNQKJFYSDTJRPGTMFUWLVOGP", code);

            if(isCodeValid){

                String principal = authentication.getPrincipal().toString();
                String authType = "";

                if(principal.contains("authType=form")) authType = "form";
                else if(principal.contains("authType=OAuth")) authType = "OAuth";

                String role = "";

                if(authType.equals("form")){
                    Optional<FormMember> member = formMemberRepository.findById(authentication.getName());
                    if(member.isPresent()) role = member.orElse(null).getRole().toString();
                } else if(authType.equals("OAuth")){
                    Optional<OAuthMember> member = oAuthMemberRepository.findById(authentication.getName());
                    if(member.isPresent()) role = member.orElse(null).getRole().toString();
                }

            } else {
                response.setStatus(HttpServletResponse.SC_NOT_ACCEPTABLE);
                return;
            }

        }

        filterChain.doFilter(request, response);

    }
}
