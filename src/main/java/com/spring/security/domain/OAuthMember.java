package com.spring.security.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import java.io.Serializable;

@Entity(name = "OAUTH_MEMBERS")
@Data
public class OAuthMember implements Serializable {

    @Id
    private String id;

    private String oauthType;

    @OneToOne
    @JoinColumn(name = "id")
    private Member member;

    // getters, setters, etc.
}