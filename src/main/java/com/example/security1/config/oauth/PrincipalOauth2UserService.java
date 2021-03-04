package com.example.security1.config.oauth;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.config.oauth.provider.FacebookUserInfo;
import com.example.security1.config.oauth.provider.GoogleUserInfo;
import com.example.security1.config.oauth.provider.OAuth2UserInfo;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // 구글로부터 받은 userRequest data에 대한 후처리되는 함수
    // 함수 종료 시 @AuthenticationPrincipal 어노테이션 활성화
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getAccessToken: " + userRequest.getAccessToken());
        System.out.println("getAdditionalParameters: " + userRequest.getAdditionalParameters());
        System.out.println("getClientRegistration: " + userRequest.getClientRegistration());
        // 구글 로그인 버튼 클릭 -> 구글 로그인창 -> 로그인 완료 -> code 리턴(oAuth-client 라이브러리가 받음)
        // -> 해당 코드로 AccessToken 요청(까지가 userRequest 정보)
        // -> 이걸로 회원프로필을 받아야 함(이 때 쓰는게 loadUser 함수) -> 회원 프로필 받음
        // loadUSer: 구글로부터 회원프로필을 받아주는 함수
        System.out.println("loadUser: " + super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User.getAttributes());

        // 회원가입 강제로 할 예정
        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")){
            System.out.println("구글 로그");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            System.out.println("facebook");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else {
            System.out.println("구글, 페이스북만 지원");
        }

        String provider = oAuth2UserInfo.getProvider(); // google
        String providerId = oAuth2UserInfo.getProviderId();
        String email = oAuth2UserInfo.getEmail();
        String username = provider + "_" + providerId; // google_12312312312 -> 중복 X
        String password = bCryptPasswordEncoder.encode("예제");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null) {
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }

        // 이 반환값이 Authentication 객체에(세션에 저장됨) 들어감
        // 일반 로그인은 PrincipalDetailsService에서 처리되어 user 정보만 담고있지만
        // OAuth2 로그인은 여기서 처리되어 user 정보와 함께 oauth2 정보도 함께 담고 있음
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
