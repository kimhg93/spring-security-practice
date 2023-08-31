package com.spring.security.domain;

import lombok.Data;

import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;

@MappedSuperclass
@Data
public class Member {

    @Id
    private String id;
    private String name;

    @Enumerated(EnumType.STRING)
    private Role role;

}
