package com.spring.security.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.Id;

@Entity(name = "OAUTH_MEMBERS")
@Data
public class OAuthMember extends Member{

    private String oauthType;

}
