package capston2024.bustracker.controller;

import capston2024.bustracker.config.dto.ApiResponse;
import capston2024.bustracker.config.dto.CodeRequestDTO;
import capston2024.bustracker.exception.ResourceNotFoundException;
import capston2024.bustracker.exception.UnauthorizedException;
import capston2024.bustracker.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

/**
 * 웹 MVC의 컨트롤러 역할
 * 계정 정보 유효성 검사 및 인증 관련 API 제공
 */
@RestController
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @GetMapping("/user")
    public ResponseEntity<ApiResponse<Map<String,Object>>> getUser(@AuthenticationPrincipal OAuth2User principal) {
        log.info("Received request for user details. Principal: {}", principal);
        if (principal == null) {
            log.warn("No authenticated user found");
            throw new UnauthorizedException("인증된 사용자를 찾을 수 없습니다");
        }
        Map<String, Object> obj = authService.getUserDetails(principal);
        log.debug("User details retrieved successfully: {}", obj);
        return ResponseEntity.ok(new ApiResponse<>(obj, "성공적으로 유저의 정보를 조회하였습니다."));
    }

    @PostMapping("/withdrawal")
    @Operation(summary = "회원 탈퇴",
            description = "현재 인증된 사용자의 계정을 삭제하고 회원 탈퇴를 처리합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "회원 탈퇴 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "500", description = "회원 탈퇴 처리 중 오류 발생")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<Boolean>> withdrawal(
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal,
            @Parameter(hidden = true) HttpServletRequest request,
            @Parameter(hidden = true) HttpServletResponse response) {

        log.info("회원탈퇴 요청 - Principal: {}", principal);

        if (principal == null) {
            log.warn("No authenticated user found");
            throw new UnauthorizedException("인증된 사용자를 찾을 수 없습니다");
        }

        boolean isSuccess = authService.withdrawUser(principal);

        if (isSuccess) {
            // 회원탈퇴 성공 후 로그아웃 처리
            authService.logout(request, response);
            return ResponseEntity.ok(new ApiResponse<>(true, "회원탈퇴가 성공적으로 처리되었습니다."));
        } else {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(false, "회원탈퇴 처리 중 오류가 발생했습니다."));
        }
    }

    /**
     * 일반 사용자 → 인증된 사용자 등급 승급
     */
    @PostMapping("/rankUp")
    @Operation(summary = "사용자 권한 승급",
            description = "조직 코드를 통해 게스트 사용자를 인증된 사용자로 권한 승급합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "권한 승급 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "잘못된 인증 코드"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<Boolean>> rankUpUser(
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal,
            @Parameter(description = "조직 인증 코드") @RequestBody CodeRequestDTO requestDTO) {

        log.info("사용자 권한 승급 요청 - 코드: {}", requestDTO.getCode());

        if (principal == null) {
            log.warn("인증된 사용자를 찾을 수 없음");
            throw new UnauthorizedException("인증된 사용자를 찾을 수 없습니다");
        }

        boolean isRankUp = authService.rankUpGuestToUser(principal, requestDTO.getCode());

        if (isRankUp) {
            return ResponseEntity.ok(new ApiResponse<>(true, "성공적으로 사용자 등급이 업그레이드되었습니다."));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>(false, "잘못된 인증 코드입니다."));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Boolean>> logout(HttpServletRequest request, HttpServletResponse response) {
        authService.logout(request, response);
        return ResponseEntity.ok(new ApiResponse<>(true, "성공적으로 로그아웃을 하였습니다."));
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ApiResponse<Boolean>> handleUnauthorizedException(UnauthorizedException ex) {
        log.error("인가되지 않은 리소스: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse<>(false, ex.getMessage()));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Boolean>> handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.error("찾을 수 없는 리소스: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiResponse<>(false, ex.getMessage()));
    }
}