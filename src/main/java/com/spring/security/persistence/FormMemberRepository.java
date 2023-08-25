package com.spring.security.persistence;

import com.spring.security.domain.FormMember;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FormMemberRepository extends JpaRepository<FormMember, String> {

}
