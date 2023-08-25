package com.spring.security.authentication;

import com.spring.security.domain.FormMember;
import com.spring.security.persistence.FormMemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class FormUserDetailService implements UserDetailsService {

    private final FormMemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<FormMember> member = memberRepository.findById(username);

        if (member.isPresent()) {
            FormMember m = member.get();
            FormUserDetail userDetail = new FormUserDetail();

            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_"+m.getRole().toString()));

            Map<String, Object> map = new HashMap<>();
            map.put("id", m.getId());
            map.put("name", m.getName());

            userDetail.setUsername(m.getId());
            userDetail.setAttributes(map);
            userDetail.setPassword(m.getPassword());
            userDetail.setAuthorities(authorities);

            return userDetail;

        } else throw new UsernameNotFoundException("User not found: " + username);

    }
}
