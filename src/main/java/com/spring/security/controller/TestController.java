package com.spring.security.controller;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.util.HashMap;
import java.util.Map;


@Controller
@RequiredArgsConstructor
@Slf4j
public class TestController {



    @GetMapping(value = "/login")
    public String testPage(){
        return "/login";
    }

    @GetMapping(value = "/home")
    public ResponseEntity<String> home(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("Controller >  " + authentication.toString());
        return ResponseEntity.ok().body(authentication.toString());
    }





//    @GetMapping(value = "/oauth2/github")
//    public ResponseEntity<Map<String, Object>> callback(@RequestParam String code){
//
//        System.err.println("########## " + code);
//
//        Map<String, Object> body = new HashMap<>();
//
//        body.put("code", code);
//        body.put("client_id", "8661138ae62267e7d75e");
//        body.put("client_secret", "96a7dcec73e287d5c904b5c584194cf4c68685bb");
//
//        String response = WebClient.builder().build()
//                .post()
//                .uri("https://github.com/login/oauth/access_token")
//                .bodyValue(body)
//                .retrieve()
//                .bodyToMono(String.class)
//                .block();
//
//        Map<String, Object> map = new HashMap<>();
//
//        UriComponentsBuilder.fromUriString("?" + response).build()
//                .getQueryParams()
//                .forEach((k, v) -> map.put(k, v.get(0)));
//
//        System.err.println(map.toString());
//
//        System.err.println(map.get("access_token"));
//
//        Map<String, Object> response2 = WebClient.builder().build()
//                .get()
//                .uri("https://api.github.com/user")
//                .header("Authorization", "Bearer " + map.get("access_token"))  // Bearer 토큰 설정
//                .retrieve()
//                .bodyToMono(Map.class)
//                .block();
//
//
//        System.err.println(response2.toString());
//
//        return ResponseEntity.ok().body(null);
//    }
//    private final AuthenticationManagerBuilder authenticationManagerBuilder;
//    private final JwtTokenProvider jwtTokenProvider;
//    private String reToken;
//
//    @CrossOrigin
//    @PostMapping(value = "/auth/token")
//    public ResponseEntity<JwtToken> generate(@RequestBody User tokenDto) {
//        log.info("(line 50) {}, {}", tokenDto.getId(), tokenDto.getName());
//
//        Map<String, Object> body = new HashMap<>();
//        body.put("name", "name1234");
//
//        log.info(tokenDto.toString());
//
//        Authentication authentication = new UsernamePasswordAuthenticationToken(tokenDto.getId(), tokenDto.getName());
//        JwtToken jwtToken = jwtTokenProvider.generateToken(authentication, body);
//
//        log.info("Generate accessToken(line 61) : {}", jwtToken.getAccessToken());
//        log.info("Generate refreshToken(line 62) : {}", jwtToken.getRefreshToken());
//        reToken = jwtToken.getAccessToken();
//
//        encryptTest("apiPracticeTest1234");
//        HttpHeaders headers = new HttpHeaders();
//        headers.setAccessControlAllowOrigin(null);
//
//        return ResponseEntity.ok()
//                .headers(headers)
//                .body(jwtToken);
//    }
//
//    @PostMapping(value = "/api")
//    public ResponseEntity<Map<String, Object>> postApiTest(@RequestBody String body) {
//        log.info("/api request body(line 76) : {} ", body);
//        Map<String, Object> map = new HashMap<>();
//        map.put("test1", "api called");
//        map.put("test2", "ok");
//        return ResponseEntity.status(HttpStatus.OK)
//                .body(map);
//    }
//
//    @PostMapping("/auth/api")
//    public Flux<Map> api(@RequestBody String refreshToken) {
//        WebClient webClient = WebClient.builder()
//                .baseUrl("http://localhost:8080/api")
//                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
//                .build();
//
//        log.info("RefreshToken(line 91) : {}", refreshToken);
//
//        Map<String, Object> body = new HashMap<>();
//        body.put("body", "request test");
//
//        log.info("/api/auth token(line 96) : {} ", reToken);
//        Flux<Map> response = webClient.post()
//                .headers((h) -> h.setBearerAuth(reToken))
//                .body(Flux.just(body), Map.class)
//                .retrieve()
//                .bodyToFlux(Map.class);
//
//        log.info("/api/auth response body(line 103) : {} ", response.blockFirst());
//        return response;
//
//    }
//
//
//    public void encryptTest(String key) {
//        // ek=be sk=be, db=sk db=ek
//        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
//
//        encryptor.setAlgorithm("PBEWithMD5AndDES");
//        encryptor.setPassword("encryptKey123");
//
//        log.info("general(line 136) : {}", key);
//
//        String base64 = Base64Utils.encodeToString(key.getBytes());
//        String encrypt = encryptor.encrypt(base64);
//        log.info("encode base64(line 140) : {}", base64);
//        log.info("encrypt base64(line 141) : {}", encrypt);
//
//
//        String decrypt = encryptor.decrypt(encrypt);
//        String decoded = new String(Base64Utils.decodeFromString(decrypt));
//        log.info("decrypt base64(line 146) : {}", decrypt);
//        log.info("decode base64(line 147) : {}", decoded);
//    }
//
//
//    @GetMapping("/auth/call")
//    public void test() {
//        String url = "http://localhost:18090/generate";
//
//        Map<String, Object> req = new HashMap<>();
//        req.put("original", "https://gitlab.kr.kworld.kpmg.com/its-dev/asp/iis501/-/branches/active");
//
//        WebClient webClient = WebClient.builder()
//                .baseUrl(url)
//                .defaultHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
//                .build();
//
//        Flux<Map> responseFlux = webClient.post()
//                .body(BodyInserters.fromValue(req))
//                .retrieve()
//                .bodyToFlux(Map.class);
//
//        responseFlux.subscribe(res -> System.err.println(res.toString()));
//
//    }
}