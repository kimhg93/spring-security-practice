package com.spring.security.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.Id;

@Entity(name = "oauth_members")
@Data
public class OAuthMember {

    @Id
    private String id;
    private String name;
    private String oauthType;
    @Enumerated(EnumType.STRING)
    private Role role;

}
