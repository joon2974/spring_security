package com.example.security1.config.auth;

// 시큐리티가 /login을 낚아채서 로그인을 진행
// 로그인 진행이 완료가 되면 시큐리티 세션을 만들어줌
// 같은 세션 공간에 시큐리티가 자신만의 시큐리티 세션 공간을 가짐
// (Security ContextHolder)에 세션 정보를 저장
// 저장할 수 있느 오브젝트 타입이 정해져 있음 => Authentication 타입의 객체
// Authentication 안에 User 정보가 있어야 함
// User 오브젝트 타입 => UserDetails 타입 객체

// Security Session 영역에 세션 정보를 저장
// 여기에 저장될 수 있는 객체가 Authentication 타입의 객체
// 그 Authentication 이라는 객체 안에 유저 정보를 저장할 때는
// UserDetails 타입의 객체로만 저장 가능

import com.example.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

// UserDetails 의 구현체이므로 PrincipalDetails 를 Authentication 객체에 넣을 수 있다.
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user; // 컴포지션
    private Map<String, Object> attributes;

    // 일반 로그인 생성자
    public PrincipalDetails(User user) {
        this.user = user;
    }

    // OAuth 로그인 생성자
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    // 해당 User의 권한을 리턴하는 곳!
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // ArrayList 는 Collection의 자식
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 계정이 만료되지 않았는지
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정이 잠기지 않았는지
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 계정 비번이 1년이 넘지 않았는지
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정 활성화 여부
    @Override
    public boolean isEnabled() {
        // 사이트에서 1년동안 회원이 로그인 안하면 비활한다.
        // 유저에 loginData를 만들어서 이게 1년이 지났으면 false를 반환하면 됨.
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // 안쓸거
    @Override
    public String getName() {
        return null;
    }
}
