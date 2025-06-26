package capston2024.bustracker.service;

import capston2024.bustracker.domain.Auth;
import capston2024.bustracker.util.auth.OAuthAttributes;
import lombok.RequiredArgsConstructor;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Map;

/**
 * 구글 로그인 이후 가져온 사용자의 정보를 기반으로
 * 가입 및 정보 수정, 세션 저장 등의 기능을 지원
 */
@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final AuthService authService;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();

        OAuthAttributes oAuthAttributes = OAuthAttributes.of(registrationId, attributes);
        Auth auth = authService.authenticateUser(oAuthAttributes);

        // 사용자의 권한 정보를 가져옵니다.
        GrantedAuthority authority = new SimpleGrantedAuthority(auth.getRoleKey());

        // OAuth2User 객체를 생성하여 반환합니다.
        return new DefaultOAuth2User(
                Collections.singleton(authority),
                attributes,
                userNameAttributeName
        );
    }
}