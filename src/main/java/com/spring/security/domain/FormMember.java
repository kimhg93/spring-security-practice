package com.spring.security.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.Id;

@Entity(name = "Members")
@Data
public class FormMember {

    @Id
    private String id;
    private String password;
    private String name;
    @Enumerated(EnumType.STRING)
    private Role role;

}
