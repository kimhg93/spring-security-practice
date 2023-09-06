package com.spring.security.authentication;

import com.spring.security.domain.FormMember;
import com.spring.security.domain.OAuthMember;
import com.spring.security.persistence.FormMemberRepository;
import com.spring.security.persistence.OAuthMemberRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;


@RequiredArgsConstructor
public class OtpValidationFilter extends OncePerRequestFilter {

    private final FormMemberRepository formMemberRepository;
    private final OAuthMemberRepository oAuthMemberRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request
            , HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(isPreAuthUser(authentication) && validateRequest(request)) {

            if(validateOtp(authentication, request)) setNewRole(authentication, response);
            else response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            return;
        }

        filterChain.doFilter(request, response);
    }

    // 1차 로그인 여부 확인
    private boolean isPreAuthUser(Authentication authentication){
        List<GrantedAuthority> roles = (List<GrantedAuthority>) authentication.getAuthorities();
        return roles.stream()
                .anyMatch(r -> "ROLE_PRE_AUTH_USER".equalsIgnoreCase(r.toString()));
    }

    // request url 체크
    private boolean validateRequest(HttpServletRequest request){
        return "/otp/valid".equals(request.getRequestURI())
                && "GET".equalsIgnoreCase(request.getMethod());
    }

    // otp 검증
    private boolean validateOtp(Authentication auth, HttpServletRequest request){
        String pass = request.getParameter("pass");
        int code = Integer.parseInt(pass);
        GoogleAuthenticator gAuth = new GoogleAuthenticator();

        if("form".equals(getLogonType(auth))){
            Optional<FormMember> member = formMemberRepository.findById(auth.getName());
            if (member.isPresent()) {
                FormMember formMember = member.get();
                return gAuth.authorize(formMember.getMember().getOtpSecret(), code);
            }
        } else {
            Optional<OAuthMember> member = oAuthMemberRepository.findById(auth.getName());
            if (member.isPresent()) {
                OAuthMember OAuthMember = member.get();
                return gAuth.authorize(OAuthMember.getMember().getOtpSecret(), code);
            }
        }
        return false;
    }

    private String getLogonType(Authentication authentication){
        String principal = authentication.getPrincipal().toString();

        if(principal.contains("authType=form")) return "form";
        else if(principal.contains("authType=OAuth")) return "OAuth";

        return "";
    }

    // 변경 권한 부여 호출
    private void setNewRole(Authentication authentication, HttpServletResponse response){
        if("form".equals(getLogonType(authentication))) formUserRole(authentication);
        else if("OAuth".equals(getLogonType(authentication))) oAuthUserRole(authentication);

        response.setStatus(HttpServletResponse.SC_OK);
    }

    // form login 권한 부여
    private void formUserRole(Authentication auth){
        Optional<FormMember> member = formMemberRepository.findById(auth.getName());
        if (member.isPresent()) {
            FormMember formMember = member.get();
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_" + formMember.getMember().getRole()));

            FormUserDetail userDetails = (FormUserDetail) auth.getPrincipal();
            userDetails.setAuthorities(authorities);

            Authentication newAuth =
                    new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), authorities);
            SecurityContextHolder.getContext().setAuthentication(newAuth);
        }
    }

    // oauth 권한 부여
    private void oAuthUserRole(Authentication auth){
        Optional<OAuthMember> member = oAuthMemberRepository.findById(auth.getName());
        if(member.isPresent()){
            OAuthMember oAuthMember = member.get();

            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_"+oAuthMember.getMember().getRole()));

            DefaultOAuth2User userDetails = (DefaultOAuth2User) auth.getPrincipal();
            DefaultOAuth2User user = new DefaultOAuth2User(authorities, userDetails.getAttributes(),"id");

            OAuth2AuthenticationToken newAuth =
                    new OAuth2AuthenticationToken(user
                            , authorities
                            , ((OAuth2AuthenticationToken) auth).getAuthorizedClientRegistrationId());
            SecurityContextHolder.getContext().setAuthentication(newAuth);
        }
    }

}