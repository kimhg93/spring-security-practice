package com.spring.security.persistence;

import com.spring.security.domain.OAuthMember;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuthMemberRepository extends JpaRepository<OAuthMember, String> {
    Optional<OAuthMember> findByIdAndOauthType(String id, String oauthType);
}
