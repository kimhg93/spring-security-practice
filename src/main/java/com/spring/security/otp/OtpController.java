package com.spring.security.otp;

import com.spring.security.domain.FormMember;
import com.spring.security.domain.OAuthMember;
import com.spring.security.mail.CustomMailSender;
import com.spring.security.persistence.FormMemberRepository;
import com.spring.security.persistence.OAuthMemberRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class OtpController {

    private final CustomMailSender mailSender;
    private final FormMemberRepository formMemberRepository;
    private final OAuthMemberRepository oAuthMemberRepository;

    @GetMapping(value = "/otp/generate")
    public ResponseEntity<String> generateKey(){
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        GoogleAuthenticatorKey googleAuthenticatorKey = gAuth.createCredentials();
        String key = googleAuthenticatorKey.getKey();

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String id = auth.getName();
        if("form".equals(getLogonType(auth))){
            Optional<FormMember> member = formMemberRepository.findById(id);
            if(member.isPresent()){
                FormMember formMember = member.get();
                formMember.getMember().setOtpSecret(key);
                formMemberRepository.save(formMember);
            }
        } else {
            Optional<OAuthMember> member = oAuthMemberRepository.findById(id);
            if(member.isPresent()){
                OAuthMember oAuthMember = member.get();
                oAuthMember.getMember().setOtpSecret(key);
                oAuthMemberRepository.save(oAuthMember);
            }
        }

        return ResponseEntity.ok().body(key);
    }

    @GetMapping(value = "/otp")
    public ModelAndView otpForm(){
        ModelAndView mv = new ModelAndView();
        mv.setViewName("/otp");
        return mv;
    }

    @GetMapping(value = "/otp/secret")
    public ResponseEntity<Boolean> otpSecret(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String id = authentication.getName();
        String secret = null;
        if("form".equals(getLogonType(authentication))){
            Optional<FormMember> member = formMemberRepository.findById(id);
            if(member.isPresent()){
                FormMember formMember = member.get();
                secret = formMember.getMember().getOtpSecret();
            }
        } else {
            Optional<OAuthMember> member = oAuthMemberRepository.findById(id);
            if(member.isPresent()){
                OAuthMember oAuthMember = member.get();
                secret = oAuthMember.getMember().getOtpSecret();
            }
        }

        return ResponseEntity.ok().body(! (secret == null || "".equals(secret)) );
    }


    @GetMapping(value = "/otp/valid")
    public void verifyCode(String pass){
        int code = Integer.parseInt(pass);
        System.err.println(code);
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        boolean isCodeValid = gAuth.authorize("V2Z4PW46MNQKJFYSDTJRPGTMFUWLVOGP", code);
    }

    private String getLogonType(Authentication authentication){
        String principal = authentication.getPrincipal().toString();

        if(principal.contains("authType=form")) return "form";
        else if(principal.contains("authType=OAuth")) return "OAuth";

        return "";
    }


}

