package com.spring.security.config;

import com.spring.security.authentication.CustomOAuth2UserService;
import com.spring.security.authentication.FormUserDetailService;
import com.spring.security.persistence.FormMemberRepository;
import com.spring.security.persistence.OAuthMemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
//@Conditional(PasswordFactorCondition.class)
@Slf4j
public class SecurityConfig {

    private final FormMemberRepository formMemberRepository;
    private final OAuthMemberRepository oAuthMemberRepository;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login/**", "/oauth2/**").permitAll()
                .anyRequest().authenticated()
                .and()

                //form login
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler((request, response, authentication) ->
                                response.setStatus(HttpStatus.OK.value()))
                        .failureHandler((request, response, exception) -> {
                                    exception.printStackTrace();
                                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                                }))
                // oauth
                .oauth2Login(oauth -> oauth
                        .loginPage("/login")
                        .defaultSuccessUrl("/home")
                        .userInfoEndpoint()
                        .userService(oAuth2UserService()))

                .csrf().disable();

        return http.build();
    }

    @Bean
    public CustomOAuth2UserService oAuth2UserService(){
        return new CustomOAuth2UserService(oAuthMemberRepository);
    }

    @Bean
    public FormUserDetailService userDetailsService(){
        return new FormUserDetailService(formMemberRepository);
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
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

}