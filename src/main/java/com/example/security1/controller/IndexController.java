package com.example.security1.controller;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody
    String loginTest(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) { //DI(의존성 주입)
        // @Authentication principal을 통해 세션 정보에 접근
        // 1번째 방법(다운 캐스팅, DI)
        System.out.println("/test/login =============");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication: " + principalDetails.getUser());

        // 2번째 방법(어노테이션)
        System.out.println("userDetails: " + userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody
    String loginOAuthTest(Authentication authentication, @AuthenticationPrincipal OAuth2User o2User) { //DI(의존성 주입)
        // @Authentication principal을 통해 세션 정보에 접근
        // 1번째 방법(다운 캐스팅, DI)
        System.out.println("/test/login =============");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication: " + oAuth2User.getAttributes());

        System.out.println("o2User: " + o2User.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    // 로그인 한 사람만
    // OAuth로그인을 해도 PrincipalDetails로 받고
    // 일반 로그인을 해도 PrincipalDetails로 받을 수 있다.
    @GetMapping("/user")
    public @ResponseBody
    String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails: " + principalDetails.getUser());
        return "user";
    }

    // 로그인 사람 주 어드민 권한 있는 사람
    @GetMapping("/admin")
    public @ResponseBody
    String admin() {
        return "admin";
    }

    // 로그인 사람 중 매니저 권한 있는 사람
    @GetMapping("/manager")
    public @ResponseBody
    String manager() {
        return "manager";
    }

    // 시큐리티가 낚아챔 - SecurityConfig 파일 생성 후 작동안함.
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    // 로그인 안 한사람도 가능
    @PostMapping("/join")
    public String join(User user) {
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    // 특성 메서드에 권한 걸고 싶으면 이렇게 걸면 됨(하나만 걸 떄)
    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody
    String info() {
        return "개인정보";
    }

    // data 메서드 실행 직전에 실행됨(권한 여러개 걸 때)
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody
    String data() {
        return "데이터 정보";
    }
}
