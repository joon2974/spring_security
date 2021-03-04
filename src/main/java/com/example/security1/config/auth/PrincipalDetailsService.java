package com.example.security1.config.auth;

import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 loginProcessingUrl("/login")
// /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는
// loadUserByUsername 함수가 실행됨!!! 규칙임
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // 변수 이름을 넘어오는 파라미터랑 무조건 같게 맞춰줘야 함!!(username)
    // 바꾸고 싶으면 SecurityConfig 에서 .usernameParameter("파람")으로 바꿀 수는 있음
    // 이 함수의 리턴값은 어디로 가나?
    // 시큐리티 세션 > Authentication > UserDetails
    // 시큐리티 Session(내부 Authentication(내부 UserDetails))
    // 결국 이 함수가 리턴 될 때 그 값이 authentication 내부에 들어가고
    // 그 값이 시큐리티 Session 에 저장됨
    // 함수 종료 시 @AuthenticationPrincipal 어노테이션 활성화
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        if (userEntity != null) {
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
