package capston2024.bustracker.controller;

import capston2024.bustracker.domain.Auth;
import capston2024.bustracker.exception.UnauthorizedException;
import capston2024.bustracker.handler.JwtTokenProvider;
import capston2024.bustracker.repository.AuthRepository;
import capston2024.bustracker.service.AuthService;
import capston2024.bustracker.service.BusService;
import capston2024.bustracker.service.RouteService;
import capston2024.bustracker.service.StationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;

@Controller
@RequestMapping("/staff")
@RequiredArgsConstructor
@Slf4j
public class StaffController {

    private final AuthService authService;
    private final BusService busService;
    private final RouteService routeService;
    private final StationService stationService;
    private final JwtTokenProvider tokenProvider;
    private final AuthRepository authRepository;

    @Value("${KAKAO_JAVASCRIPT_KEY}")
    private String kakaoApiKey;

    @GetMapping("/login")
    public String loginPage() {
        return "staff/login";
    }

    @GetMapping("/dashboard")
    public String dashboard(@RequestParam(required = false) String token,
                            @AuthenticationPrincipal OAuth2User principal,
                            Model model) {

        log.info("대시보드 접근 - Principal: {}, Token: {}", principal, token);

        String organizationId = null;
        Map<String, Object> userInfo = null;

        try {
            // 1. OAuth2 사용자인 경우 (일반 OAuth2 로그인)
            if (principal != null) {
                log.info("OAuth2 사용자로 접근");
                userInfo = authService.getUserDetails(principal);
                organizationId = (String) userInfo.get("organizationId");
            }
            // 2. 토큰을 통한 접근인 경우 (STAFF 로그인)
            else if (token != null && !token.trim().isEmpty()) {
                log.info("토큰을 통한 접근: {}", token);

                try {
                    // JWT 토큰 유효성 검증
                    if (!tokenProvider.validateToken(token)) {
                        log.error("유효하지 않은 토큰");
                        throw new UnauthorizedException("유효하지 않은 토큰입니다.");
                    }

                    // 토큰에서 직접 이메일 추출
                    String email = tokenProvider.getEmailFromToken(token);
                    if (email == null || email.isEmpty()) {
                        // 이메일이 없으면 사용자명을 이메일로 사용
                        email = tokenProvider.getUsernameFromToken(token);
                    }

                    log.info("토큰에서 추출한 이메일: {}", email);

                    if (email == null || email.isEmpty()) {
                        log.error("토큰에서 사용자 정보를 추출할 수 없습니다.");
                        throw new UnauthorizedException("토큰에서 사용자 정보를 추출할 수 없습니다.");
                    }

                    // 사용자 정보 조회
                    String finalEmail = email;
                    Auth auth = authRepository.findByEmail(email)
                            .orElseThrow(() -> new UnauthorizedException("사용자를 찾을 수 없습니다: " + finalEmail));

                    // SecurityContext에 인증 정보 설정
                    Authentication authentication = tokenProvider.getAuthentication(token);
                    SecurityContextHolder.getContext().setAuthentication(authentication);

                    // userInfo 구성
                    userInfo = Map.of(
                            "인증 상태", true,
                            "name", auth.getName(),
                            "email", auth.getEmail(),
                            "role", auth.getRoleKey(),
                            "organizationId", auth.getOrganizationId()
                    );

                    organizationId = auth.getOrganizationId();
                    log.info("토큰 인증 성공 - 조직 ID: {}", organizationId);

                } catch (Exception e) {
                    log.error("토큰 인증 실패: {}", e.getMessage());
                    return "redirect:/staff/login";
                }
            }
            // 3. 현재 SecurityContext에서 인증 정보 확인 (이미 로그인된 상태)
            else {
                Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
                log.info("현재 인증 상태: {}", currentAuth);

                if (currentAuth != null && currentAuth.isAuthenticated() &&
                        !currentAuth.getPrincipal().equals("anonymousUser")) {

                    try {
                        // 현재 인증된 사용자의 이메일 추출
                        String email = null;
                        if (currentAuth.getPrincipal() instanceof OAuth2User) {
                            OAuth2User oAuth2User = (OAuth2User) currentAuth.getPrincipal();
                            email = (String) oAuth2User.getAttributes().get("email");
                        } else {
                            // 다른 타입의 Principal인 경우 이름을 이메일로 사용
                            email = currentAuth.getName();
                        }

                        log.info("현재 인증된 이메일: {}", email);

                        if (email != null) {
                            Auth auth = authRepository.findByEmail(email)
                                    .orElseThrow(() -> new UnauthorizedException("사용자를 찾을 수 없습니다."));

                            userInfo = Map.of(
                                    "인증 상태", true,
                                    "name", auth.getName(),
                                    "email", auth.getEmail(),
                                    "role", auth.getRoleKey(),
                                    "organizationId", auth.getOrganizationId()
                            );

                            organizationId = auth.getOrganizationId();
                            log.info("현재 인증 성공 - 조직 ID: {}", organizationId);
                        }
                    } catch (Exception e) {
                        log.error("현재 인증 정보 처리 실패: {}", e.getMessage());
                        return "redirect:/staff/login";
                    }
                } else {
                    log.warn("인증 정보가 없음");
                    return "redirect:/staff/login";
                }
            }

            // 인증된 사용자 정보가 없으면 로그인 페이지로
            if (userInfo == null || organizationId == null || organizationId.isEmpty()) {
                log.warn("사용자 정보 또는 조직 ID가 없음");
                return "redirect:/staff/login";
            }

            // 모델에 정보 추가
            model.addAttribute("user", userInfo);
            model.addAttribute("token", token);
            model.addAttribute("kakaoApiKey", kakaoApiKey); // 카카오 API 키 추가

            // 조직의 버스, 라우트, 정류장 정보 로드
            try {
                model.addAttribute("buses", busService.getAllBusStatusByOrganizationId(organizationId));
                model.addAttribute("routes", routeService.getAllRoutesByOrganizationId(organizationId));
                model.addAttribute("stations", stationService.getAllStations(organizationId));

                log.info("대시보드 데이터 로드 완료 - 조직 ID: {}", organizationId);
            } catch (Exception e) {
                log.error("대시보드 데이터 로드 실패: {}", e.getMessage());
                // 데이터 로드 실패해도 대시보드는 표시
                model.addAttribute("buses", java.util.Collections.emptyList());
                model.addAttribute("routes", java.util.Collections.emptyList());
                model.addAttribute("stations", java.util.Collections.emptyList());
            }

            return "staff/dashboard";

        } catch (Exception e) {
            log.error("대시보드 접근 중 예외 발생: {}", e.getMessage(), e);
            return "redirect:/staff/login";
        }
    }
}