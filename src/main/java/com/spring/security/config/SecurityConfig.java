package com.spring.security.config;

import com.spring.security.authentication.*;
import com.spring.security.jwt.JwtAuthenticationFilter;
import com.spring.security.jwt.JwtTokenProvider;
import com.spring.security.persistence.FormMemberRepository;
import com.spring.security.persistence.OAuthMemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
//@Conditional(PasswordFactorCondition.class)
@Slf4j
/**
 * id/pw
 * oAuth2 (kakao, naver, google, github)
 * jwt
 * sms
 * mail
 * 인증서
 * xss
 * csrf
 *
 */
public class SecurityConfig {

    private final FormMemberRepository formMemberRepository;
    private final OAuthMemberRepository oAuthMemberRepository;
    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http

                .authorizeRequests()
                .antMatchers("/home").hasRole("MEMBER")
                .antMatchers("/otp", "/otp/**").hasRole("PRE_AUTH_USER")
                .antMatchers(getNonAuthPattern()).permitAll()
                .expressionHandler(expressionHandler())
                .anyRequest().authenticated()
                .and()

                .exceptionHandling()
                .authenticationEntryPoint(customAuthenticationEntryPoint())
                .accessDeniedHandler(customAccessDeniedHandler())
                .and()

                //form login
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler(new LoginSuccessHandler())
                        .failureHandler((request, response, exception) -> {
                            exception.printStackTrace();
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                        }))
                // oauth
                .oauth2Login(oauth -> oauth
                        .loginPage("/login")
                        .defaultSuccessUrl("/otp")
                        .userInfoEndpoint()
                        .userService(oAuth2UserService()))

                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new OtpValidationFilter(formMemberRepository, oAuthMemberRepository)
                        , FilterSecurityInterceptor.class)

                .csrf().disable();

        return http.build();
    }

    private String[] getNonAuthPattern() {
        return new String[]{"/login/**"
                , "/oauth2/**"
                , "/auth/**"
                , "/mail/**"
                , "/favicon.ico"
                , "/otp/**"};
    }


    @Bean
    public CustomOAuth2UserService oAuth2UserService() {
        return new CustomOAuth2UserService(oAuthMemberRepository);
    }

    @Bean
    public FormUserDetailService userDetailsService() {
        return new FormUserDetailService(formMemberRepository);
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtTokenProvider);
    }

    @Bean
    public AuthenticationEntryPointImpl customAuthenticationEntryPoint() {
        return new AuthenticationEntryPointImpl();
    }

    @Bean
    public AccessDeniedHandlerImpl customAccessDeniedHandler() {
        return new AccessDeniedHandlerImpl();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_ADMIN > ROLE_MANAGER\n" +
                "ROLE_MANAGER > ROLE_MEMBER\n" +
                "ROLE_MEMBER > ROLE_USER\n" +
                "ROLE_USER > ROLE_PRE_AUTH_USER");
        return hierarchy;
    }

    @Bean
    public AccessDecisionManager accessDecisionManager() {
        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
        return new AffirmativeBased(Arrays.asList(roleHierarchyVoter));
    }

    @Bean
    public SecurityExpressionHandler<FilterInvocation> expressionHandler() {
        DefaultWebSecurityExpressionHandler webSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
        webSecurityExpressionHandler.setRoleHierarchy(roleHierarchy());
        return webSecurityExpressionHandler;
    }




}
//    OAuth JavaConfig
//
//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository() {
//        return new InMemoryClientRegistrationRepository(
//                googleClientRegistration(),
//                githubClientRegistration(),
//                kakaoClientRegistration(),
//                naverClientRegistration()
//        );
//    }
//
//    private ClientRegistration googleClientRegistration() {
//        return ClientRegistration.withRegistrationId("google")
//                .clientId("")
//                .clientSecret("")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
//                .scope("openid", "profile", "email")
//                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
//                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
//                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
//                .issuerUri("https://accounts.google.com")
//                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
//                .userNameAttributeName(IdTokenClaimNames.SUB)
//                .clientName("Google")
//                .build();
//    }
//
//    private ClientRegistration githubClientRegistration() {
//        return ClientRegistration.withRegistrationId("github")
//                .clientId("")
//                .clientSecret("")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
//                .scope("read:user")
//                .authorizationUri("https://github.com/login/oauth/authorize")
//                .tokenUri("https://github.com/login/oauth/access_token")
//                .userInfoUri("https://api.github.com/user")
//                .userNameAttributeName("id")
//                .clientName("Github")
//                .build();
//    }
//
//    private ClientRegistration naverClientRegistration() {
//        return ClientRegistration.withRegistrationId("naver")
//                .clientId("")
//                .clientSecret("")
//                .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
//                .scope("name", "email")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationUri("https://nid.naver.com/oauth2.0/authorize")
//                .tokenUri("https://nid.naver.com/oauth2.0/token")
//                .userInfoUri("https://openapi.naver.com/v1/nid/me")
//                .userNameAttributeName("response")
//                .clientName("Naver")
//                .build();
//    }
//
//    private ClientRegistration kakaoClientRegistration() {
//        return ClientRegistration.withRegistrationId("kakao")
//                .clientId("")
//                .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
//                .scope("profile_nickname", "account_email")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationUri("https://kauth.kakao.com/oauth/authorize")
//                .tokenUri("https://kauth.kakao.com/oauth/token")
//                .userInfoUri("https://kapi.kakao.com/v2/user/me")
//                .userNameAttributeName("id")
//                .clientName("Kakao")
//                .build();
//    }


