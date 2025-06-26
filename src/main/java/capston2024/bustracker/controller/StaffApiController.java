package capston2024.bustracker.controller;

import capston2024.bustracker.config.dto.ApiResponse;
import capston2024.bustracker.config.status.Role;
import capston2024.bustracker.domain.Auth;
import capston2024.bustracker.domain.Token;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.exception.TokenException;
import capston2024.bustracker.exception.UnauthorizedException;
import capston2024.bustracker.handler.JwtTokenProvider;
import capston2024.bustracker.repository.UserRepository;
import capston2024.bustracker.service.AuthService;
import capston2024.bustracker.service.PasswordEncoderService;
import capston2024.bustracker.service.TokenService;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

// Swagger 어노테이션 추가
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.media.ExampleObject;

@RestController
@RequestMapping("/api/staff")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Staff", description = "조직 관리자 인증 관련 API")
public class StaffApiController {
    private final AuthService authService; // AuthService 주입

    /**
     * 조직 관리자 로그인
     */
    @PostMapping("/login")
    @Operation(summary = "조직 관리자 로그인",
            description = "조직 ID와 비밀번호를 사용하여 조직 관리자 계정으로 로그인합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "로그인 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "필수 입력값 누락"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증 실패 (잘못된 조직 ID 또는 비밀번호)"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "관리자 계정이 아님")
    })
    public ResponseEntity<ApiResponse<Map<String, String>>> login(
            @RequestBody Map<String, String> loginRequest) {

        String organizationId = loginRequest.get("organizationId");
        String password = loginRequest.get("password");

        if (organizationId == null || password == null) {
            throw new BusinessException("조직 ID와 비밀번호를 모두 입력해주세요.");
        }

        Map<String, String> response = authService.loginStaff(organizationId, password);

        return ResponseEntity.ok(new ApiResponse<>(response, "로그인 성공"));
    }

    /**
     * 비즈니스 예외 처리
     */
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse<Void>> handleBusinessException(BusinessException ex) {
        log.error("비즈니스 예외 발생: {}", ex.getMessage());

        HttpStatus status = switch (ex.getErrorCode()) {
            case USER_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case DUPLICATE_ENTITY -> HttpStatus.CONFLICT;
            case ACCESS_DENIED -> HttpStatus.FORBIDDEN;
            case INVALID_TOKEN, TOKEN_EXPIRED -> HttpStatus.UNAUTHORIZED;
            default -> HttpStatus.BAD_REQUEST;
        };

        return ResponseEntity.status(status)
                .body(new ApiResponse<>(null, ex.getMessage()));
    }

    /**
     * 인증 예외 처리
     */
    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ApiResponse<Void>> handleUnauthorizedException(UnauthorizedException ex) {
        log.error("인증 예외 발생: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse<>(null, ex.getMessage()));
    }

    /**
     * 토큰 예외 처리
     */
    @ExceptionHandler({TokenException.class, ExpiredJwtException.class})
    public ResponseEntity<ApiResponse<Void>> handleTokenException(Exception ex) {
        log.error("토큰 예외 발생: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse<>(null, "토큰이 유효하지 않거나 만료되었습니다."));
    }

    /**
     * 잘못된 요청 형식 예외 처리
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Void>> handleIllegalArgumentException(IllegalArgumentException ex) {
        log.error("잘못된 요청 형식: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse<>(null, "잘못된 요청 형식입니다."));
    }

    /**
     * 일반 예외 처리
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneralException(Exception ex) {
        log.error("예기치 않은 오류 발생", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiResponse<>(null, "서버 오류가 발생했습니다."));
    }
}