package com.spring.security.domain;

import lombok.Data;

import javax.persistence.*;

@Entity(name = "MEMBERS")
@Data
public class Member {

    @Id
    @Column(length = 100)
    private String id;
    private String name;
    private String otpSecret;

    @Enumerated(EnumType.STRING)
    private Role role;

    @OneToOne(mappedBy = "member", cascade = CascadeType.ALL)
    private FormMember formMember;

    @OneToOne(mappedBy = "member", cascade = CascadeType.ALL)
    private OAuthMember oauthMember;

    @OneToOne(mappedBy = "member", cascade = CascadeType.ALL)
    private TokenMember tokenMember;

    // getters, setters, etc.
}
