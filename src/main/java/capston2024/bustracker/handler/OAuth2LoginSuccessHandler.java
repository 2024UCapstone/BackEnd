package capston2024.bustracker.handler;

import capston2024.bustracker.config.status.Role;
import capston2024.bustracker.domain.auth.TokenInfo;
import capston2024.bustracker.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;
    private final TokenService tokenService;
//    private static final String URI = "https://devse.gonetis.com";
    private static final String URI = "http://localhost:3000";

    private static final long REFRESH_TOKEN_ROTATION_TIME = 1000 * 60 * 60 * 24 * 7L; // 7일

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String username = authentication.getName();
        TokenInfo existingToken = tokenService.findByUserName(username);

        String accessToken;
        if (existingToken != null && tokenProvider.validateToken(existingToken.getRefreshToken())) {
            // 리프레시 토큰의 만료 시간 확인
            long refreshTokenRemainTime = tokenProvider.getTokenExpirationTime(existingToken.getRefreshToken());

            if (refreshTokenRemainTime > REFRESH_TOKEN_ROTATION_TIME) {
                // 리프레시 토큰이 아직 충분히 유효한 경우
                accessToken = tokenProvider.reissueAccessToken(existingToken.getAccessToken());
            } else {
                // 리프레시 토큰의 만료가 임박한 경우 새로운 토큰 세트 발급
                accessToken = tokenProvider.generateAccessToken(authentication);
                tokenProvider.generateRefreshToken(authentication, accessToken);
            }
        } else {
            // 새로운 토큰 세트 발급
            accessToken = tokenProvider.generateAccessToken(authentication);
            tokenProvider.generateRefreshToken(authentication, accessToken);
        }

        String redirectUri = determineTargetUrl(authentication);

        // 토큰 전달을 위한 redirect
        String redirectUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("token", accessToken)
                .build().toUriString();

        response.sendRedirect(redirectUrl);
    }

        protected String determineTargetUrl(Authentication authentication) {
            if (authentication.getAuthorities().contains(new SimpleGrantedAuthority(Role.GUEST.getKey()))) {
                return URI + "/enter-code";
            } else if (authentication.getAuthorities().contains(new SimpleGrantedAuthority(Role.USER.getKey())) ||
                    authentication.getAuthorities().contains(new SimpleGrantedAuthority(Role.ADMIN.getKey()))) {
                return URI + "/home";
            } else {
                return URI;
            }
        }

}