package com.spring.security.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.Id;

@Entity(name = "TOKEN_MEMBER")
@Data
public class TokenMember {

    @Id
    private String id;
    private String name;
    private String refreshToken;
    @Enumerated(EnumType.STRING)
    private Role role;

}
