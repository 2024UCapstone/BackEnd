package capston2024.bustracker.controller;

import capston2024.bustracker.config.dto.ApiResponse;
import capston2024.bustracker.domain.Auth;
import capston2024.bustracker.domain.Organization;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.exception.UnauthorizedException;
import capston2024.bustracker.handler.JwtTokenProvider;
import capston2024.bustracker.service.AuthService;
import capston2024.bustracker.service.OrganizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Admin", description = "총관리자 관련 API")
public class AdminController {

    private final AuthService authService;
    private final OrganizationService organizationService;
    private final JwtTokenProvider tokenProvider;

    /**
     * 관리자 로그인 페이지
     */
    @GetMapping("/login")
    @Operation(summary = "관리자 로그인 페이지",
            description = "총관리자 로그인을 위한 HTML 페이지를 반환합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "로그인 페이지 반환 성공")
    })
    public String adminLoginPage() {
        return "admin/login";
    }

    /**
     * OAuth2User 또는 토큰으로 관리자 인증 처리
     */
    private OAuth2User authenticateAdmin(OAuth2User principal, String token) {
        // 1. OAuth2User principal이 있는지 확인
        if (principal != null) {
            // OAuth2 인증 완료된 경우
            log.info("OAuth2 인증된 사용자: {}", principal.getName());

            if (authService.isAdmin(principal)) {
                return principal;
            }
            log.warn("관리자 권한이 없는 사용자: {}", principal.getName());
            return null;
        }
        // 2. 토큰 파라미터가 있는지 확인
        else if (token != null && !token.isEmpty()) {
            log.info("토큰 파라미터로 인증 시도");
            try {
                // JWT 토큰 검증 및 인증 처리
                Authentication authentication = tokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // 인증된 사용자가 관리자인지 확인
                OAuth2User tokenPrincipal = (OAuth2User) authentication.getPrincipal();
                if (authService.isAdmin(tokenPrincipal)) {
                    log.info("토큰 인증 성공: {}", tokenPrincipal.getName());
                    return tokenPrincipal;
                }
                log.warn("관리자 권한이 없는 토큰: {}", tokenPrincipal.getName());
                return null;
            } catch (Exception e) {
                log.error("토큰 인증 실패: {}", e.getMessage());
                return null;
            }
        }
        // 3. 인증 정보가 없는 경우
        else {
            log.warn("인증 정보 없음");
            return null;
        }
    }

    /**
     * 총관리자 대시보드 페이지
     */
    @GetMapping("/dashboard")
    @Operation(summary = "총관리자 대시보드",
            description = "총관리자 대시보드 페이지를 반환합니다. 모든 조직 정보를 확인할 수 있습니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "대시보드 페이지 반환 성공"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "302", description = "인증 실패로 로그인 페이지로 리다이렉트")
    })
    public String adminDashboard(
            @Parameter(description = "JWT 토큰") @RequestParam(required = false) String token,
            @AuthenticationPrincipal OAuth2User principal,
            Model model) {

        log.info("Dashboard 접근 - Principal: {}, Token: {}", principal, token);

        OAuth2User authenticatedAdmin = authenticateAdmin(principal, token);
        if (authenticatedAdmin == null) {
            return "redirect:/admin/login";
        }

        // 인증 및 권한 확인 완료, 대시보드 표시
        // 모든 조직 정보 조회
        List<Organization> organizations = organizationService.getAllOrganizations();
        model.addAttribute("organizations", organizations);

        // 토큰이 있으면 이후 API 호출을 위해 모델에 추가
        if (token != null) {
            model.addAttribute("token", token);
        }

        return "admin/dashboard";
    }

    /**
     * 새로운 조직 및 관리자 계정 생성 API
     */
    @PostMapping("/api/organizations")
    @ResponseBody
    @Operation(summary = "조직 및 관리자 계정 생성",
            description = "새로운 조직과 해당 조직의 관리자 계정을 동시에 생성합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "조직 및 관리자 계정 생성 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "잘못된 요청 데이터"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<Map<String, String>>> createOrganizationAndAdmin(
            @Parameter(description = "JWT 토큰") @RequestParam(required = false) String token,
            @AuthenticationPrincipal OAuth2User principal,
            @Parameter(description = "조직 생성 요청 데이터") @RequestBody Map<String, String> request) {

        OAuth2User authenticatedAdmin = authenticateAdmin(principal, token);
        if (authenticatedAdmin == null) {
            throw new UnauthorizedException("총관리자 권한이 필요합니다.");
        }

        String organizationName = request.get("organizationName");
        String adminName = request.get("adminName");

        // 필수 값 검증
        if (organizationName == null || adminName == null) {
            throw new BusinessException("모든 필드를 입력해주세요.");
        }

        // 조직 및 관리자 계정 생성
        Map<String, String> accountInfo = authService.createOrganizationAndAdmin(organizationName, adminName);

        return ResponseEntity.ok(new ApiResponse<>(accountInfo, "조직 및 관리자 계정이 생성되었습니다."));
    }

    /**
     * 조직별 관리자 계정 목록 조회 API
     */
    @GetMapping("/api/organization-admins")
    @ResponseBody
    @Operation(summary = "조직별 관리자 계정 목록 조회",
            description = "특정 조직의 모든 관리자 계정 목록을 조회합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "관리자 계정 목록 조회 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증 실패"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "조직을 찾을 수 없음")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<List<Auth>>> getOrganizationAdmins(
            @Parameter(description = "JWT 토큰") @RequestParam(required = false) String token,
            @AuthenticationPrincipal OAuth2User principal,
            @Parameter(description = "조직 ID") @RequestParam String organizationId) {

        OAuth2User authenticatedAdmin = authenticateAdmin(principal, token);
        if (authenticatedAdmin == null) {
            throw new UnauthorizedException("총관리자 권한이 필요합니다.");
        }

        List<Auth> admins = authService.getOrganizationAdmins(organizationId);
        return ResponseEntity.ok(new ApiResponse<>(admins, "조직 관리자 계정 목록 조회 완료"));
    }

    /**
     * 관리자 비밀번호 리셋 API
     */
    @PostMapping("/api/reset-password")
    @ResponseBody
    @Operation(summary = "관리자 비밀번호 리셋",
            description = "특정 조직의 관리자 비밀번호를 새로 생성하여 리셋합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "비밀번호 리셋 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "잘못된 요청 데이터"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증 실패"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "관리자 계정을 찾을 수 없음")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<Map<String, String>>> resetPassword(
            @Parameter(description = "JWT 토큰") @RequestParam(required = false) String token,
            @AuthenticationPrincipal OAuth2User principal,
            @Parameter(description = "비밀번호 리셋 요청 데이터") @RequestBody Map<String, String> request) {

        OAuth2User authenticatedAdmin = authenticateAdmin(principal, token);
        if (authenticatedAdmin == null) {
            throw new UnauthorizedException("총관리자 권한이 필요합니다.");
        }

        String organizationId = request.get("organizationId");

        // 필수 값 검증
        if (organizationId == null) {
            throw new BusinessException("조직 ID를 입력해주세요.");
        }

        // 비밀번호 리셋 서비스 호출
        Map<String, String> newPasswordInfo = authService.resetStaffPassword(organizationId);

        return ResponseEntity.ok(new ApiResponse<>(newPasswordInfo, "비밀번호가 성공적으로 리셋되었습니다."));
    }

    /**
     * 예외 처리
     */
    @ExceptionHandler(BusinessException.class)
    @ResponseBody
    public ResponseEntity<ApiResponse<Void>> handleBusinessException(BusinessException ex) {
        log.error("비즈니스 예외 발생: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse<>(null, ex.getMessage()));
    }

    @ExceptionHandler(UnauthorizedException.class)
    @ResponseBody
    public ResponseEntity<ApiResponse<Void>> handleUnauthorizedException(UnauthorizedException ex) {
        log.error("인증 예외 발생: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse<>(null, ex.getMessage()));
    }
}