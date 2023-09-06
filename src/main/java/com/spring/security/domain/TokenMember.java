package com.spring.security.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import java.io.Serializable;

@Entity(name = "TOKEN_MEMBERS")
@Data
public class TokenMember implements Serializable {


    @Id
    private String id;

    private String refreshToken;

    @OneToOne
    @JoinColumn(name = "id")
    private Member member;

}