package capston2024.bustracker.handler;

import capston2024.bustracker.config.status.Role;
import capston2024.bustracker.domain.Token;
import capston2024.bustracker.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * OAuth2 로그인 성공 후 처리를 담당하는 핸들러
 * - 웹 환경: ADMIN은 대시보드로 리다이렉트
 * - 앱 환경: DRIVER는 DRIVER 앱으로, 나머지 모든 역할은 USER 앱으로 리다이렉트
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;
    private final TokenService tokenService;

    // 앱 스킴 URL 정의
    private static final String IOS_APP_SCHEME_URI = "org.reactjs.native.example.Busbuddybuddy://oauth2callback";
    private static final String ANDROID_APP_SCHEME_URI = "com.busbuddybuddy://oauth2callback";
    private static final long REFRESH_TOKEN_ROTATION_TIME = 1000 * 60 * 60 * 24 * 7L; // 7일

    /**
     * 인증 성공 시 호출되는 메서드
     * 사용자 토큰을 관리하고 적절한 애플리케이션으로 리다이렉트
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String username = authentication.getName();
        Token existingToken = tokenService.findByUserName(username);
        String accessToken;

        try {
            // 기존 토큰이 있고 유효한 경우 처리
            if (existingToken != null && tokenProvider.validateToken(existingToken.getRefreshToken())) {
                long refreshTokenRemainTime = tokenProvider.getTokenExpirationTime(existingToken.getRefreshToken());

                // 리프레시 토큰 순환 시간이 남아있으면 액세스 토큰만 재발급
                if (refreshTokenRemainTime > REFRESH_TOKEN_ROTATION_TIME) {
                    accessToken = tokenProvider.reissueAccessToken(existingToken.getAccessToken());
                } else {
                    // 리프레시 토큰 순환 시간이 임박하면 모든 토큰 재발급
                    accessToken = tokenProvider.generateAccessToken(authentication);
                    tokenProvider.generateRefreshToken(authentication, accessToken);
                }
            } else {
                // 기존 토큰이 없거나 유효하지 않은 경우 신규 발급
                accessToken = tokenProvider.generateAccessToken(authentication);
                tokenProvider.generateRefreshToken(authentication, accessToken);
            }

            // 디바이스 타입 감지 및 역할 기반 리다이렉션 처리
            String userAgent = request.getHeader("User-Agent");
            log.info("userAgent = {}", userAgent);

            String redirectUrl = determineRedirectUrl(userAgent, accessToken, authentication);

            // CORS 헤더 설정
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
            response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");

            // 리다이렉트 수행
            response.sendRedirect(redirectUrl);

        } catch (Exception e) {
            log.error("인증 성공 처리 중 오류 발생", e);
            throw new ServletException("Authentication failed");
        }
    }

    /**
     * 사용자 디바이스와 역할에 따른 리다이렉트 URL 결정
     * - 웹 환경: ADMIN은 관리자 페이지로, 다른 역할은 앱 안내 페이지로
     * - 앱 환경: DRIVER는 DRIVER 앱으로, ADMIN은 USER 앱으로 리다이렉트
     */
    private String determineRedirectUrl(String userAgent, String accessToken, Authentication authentication) throws IOException {
        // 토큰 URL 인코딩
        String encodedToken = URLEncoder.encode(accessToken, StandardCharsets.UTF_8.toString());

        // 사용자 역할 확인
        boolean isGuest = authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals(Role.GUEST.getKey()));
        boolean isUser = authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals(Role.USER.getKey()));
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals(Role.ADMIN.getKey()));

        // 사용자 역할 로깅
        String roleStr = isAdmin ? "총관리자" :
                            isUser ? "인증된 사용자" :
                                isGuest ? "게스트" : "알 수 없음";
        log.info("사용자 역할: {}", roleStr);

        // User-Agent가 없는 경우 처리(추후, 개발 제안)
        /*
         * REVIEWER NOTE: User-Agent가 없는 경우에 대한 예외 처리가 필요할 것으로 생각됨
         *
         * 필요한 이유
         * 1. API 테스트 도구(Postman 등)나 자동화된 테스트에서 User-Agent를 설정하지 않고 요청할 수 있음
         * 2. 보안 도구나 프록시를 사용하는 사용자가 User-Agent를 제거하고 접근할 가능성이 있음
         * 3. NullPointerException 방지를 통한 서버 안정성 확보
         * 4. 비정상적인 요청 패턴 감지를 위한 로깅 목적
         */
        if (userAgent == null) {
            log.info("설명");
            // 1. 자동화된 도구나 봇: 웹 스크래퍼, API 테스트 도구(Postman 등), 또는 일부 봇은 User-Agent 헤더를 설정하지 않고 요청을 보낼 가능성
            // 2. 보안 도구 사용: 일부 사용자는 프라이버시 보호를 위해 User-Agent를 숨기거나 제거하는 브라우저 확장 프로그램이나 프록시를 사용할 가능성
        }

        // 모바일 환경과 웹 환경 구분
        boolean isMobileDevice = isMobileDevice(userAgent);
        log.info("디바이스 타입: {}", isMobileDevice ? "모바일" : "웹");

        // 웹 환경: 관리자 계정은 해당 페이지로, 나머지는 USER 앱 안내 페이지로
        if (!isMobileDevice && isAdmin) {
            log.info("웹 사용자(총관리자) - 웹 대시보드로 리다이렉트");
            return UriComponentsBuilder
                    .fromUriString("/admin/dashboard")
                    .queryParam("token", encodedToken)
                    .build(false)
                    .toUriString();
        }
        else {
            String appSchemeUri;

            appSchemeUri = Objects.requireNonNull(userAgent).contains("iPhone")
                    ? IOS_APP_SCHEME_URI : ANDROID_APP_SCHEME_URI;
            log.info("사용자 앱에서 로그인 - 사용자 앱으로 리다이렉트");

            log.info("결정된 앱 스킴 URI: {}", appSchemeUri);

            // 앱 스킴 URL에 토큰 추가하여 리다이렉트
            return UriComponentsBuilder
                    .fromUriString(appSchemeUri)
                    .queryParam("token", encodedToken)
                    .build(false)
                    .toUriString();
        }
    }

    /**
     * User-Agent로 모바일 디바이스 여부 확인
     */
    private boolean isMobileDevice(String userAgent) {
        if (userAgent == null) {
            return false;
        }
        return userAgent.contains("Android") ||
                userAgent.contains("iPhone") ||
                userAgent.contains("iPad") ||
                userAgent.contains("iPod");
    }
}
