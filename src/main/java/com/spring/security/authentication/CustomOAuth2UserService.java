package com.spring.security.authentication;

import com.spring.security.domain.OAuthMember;
import com.spring.security.persistence.OAuthMemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final OAuthMemberRepository oAuthMemberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User user = super.loadUser(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        log.info(userRequest.getClientRegistration().toString());
        log.info(user.toString());
        log.info(user.getAttributes().toString());

        String id = "";

        if(registrationId.equalsIgnoreCase("google")){
            id = user.getAttributes().get("email").toString();
        } else if(registrationId.equalsIgnoreCase("github")){
            id = user.getAttributes().get("login").toString();
        } else if(registrationId.equalsIgnoreCase("kakao")){
            Map map = (Map) user.getAttributes().get("kakao_account");
            id = map.get("email").toString();
        } else if(registrationId.equalsIgnoreCase("naver")){
            Map map = (Map) user.getAttributes().get("response");
            id = map.get("email").toString();
        }

        Optional<OAuthMember> member = oAuthMemberRepository.findByIdAndOauthType(id, registrationId);

        return getOAuthUserService(member);
    }


    private DefaultOAuth2User getOAuthUserService(Optional<OAuthMember> member){
        List<GrantedAuthority> authorities = new ArrayList<>();

        if (member.isPresent()) {
            OAuthMember m = member.get();

            authorities.add(new SimpleGrantedAuthority("ROLE_PRE_AUTH_USER"));

            Map<String, Object> attributes = new HashMap<>();

            attributes.put("id", m.getMember().getId());
            attributes.put("username", m.getMember().getName());
            attributes.put("OAuthType", m.getOauthType());
            attributes.put("authType", "OAuth");

            return new DefaultOAuth2User(
                    authorities,
                    attributes,
                    "id");

        } else throw new UsernameNotFoundException("User not found: " + member.orElse(null).getMember().getId());
    }
}
