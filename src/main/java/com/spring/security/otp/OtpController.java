package com.spring.security.otp;

import com.spring.security.mail.CustomMailSender;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base32;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class OtpController {

    private final CustomMailSender mailSender;

//    @GetMapping(value = "/otp")
//    public ResponseEntity<String> generateKey(){
//        GoogleAuthenticator gAuth = new GoogleAuthenticator();
//        GoogleAuthenticatorKey googleAuthenticatorKey = gAuth.createCredentials();
//        String key = googleAuthenticatorKey.getKey();
//
//        mailSender.send(key);
//
//        return ResponseEntity.ok().body(key);
//    }

    @GetMapping(value = "/otp")
    public ModelAndView otpForm(){
        ModelAndView mv = new ModelAndView();
        mv.setViewName("/otp");
        return mv;
    }

    @GetMapping(value = "/otp/valid")
    public void verifyCode(String pass){
        int code = Integer.parseInt(pass);
        System.err.println(code);
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        boolean isCodeValid = gAuth.authorize("V2Z4PW46MNQKJFYSDTJRPGTMFUWLVOGP", code);
    }

}

