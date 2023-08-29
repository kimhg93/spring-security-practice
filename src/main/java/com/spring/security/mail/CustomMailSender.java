package com.spring.security.mail;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class CustomMailSender {

    private final JavaMailSender mailSender;

    public void send(String contents){

        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo("");
        mailMessage.setSubject("[test]인증번호 전송");
        mailMessage.setText("인증번호 : " + contents);
        mailMessage.setFrom("no-reply@devgon.kro.kr");

        mailSender.send(mailMessage);
    }

}
