package capston2024.bustracker.controller;

import capston2024.bustracker.config.dto.SchoolAuthRequestDTO;
import capston2024.bustracker.config.dto.SchoolRegisterDTO;
import capston2024.bustracker.config.dto.ApiResponse;
import capston2024.bustracker.exception.AdditionalAuthenticationFailedException;
import capston2024.bustracker.exception.DuplicateResourceException;
import capston2024.bustracker.exception.UnauthorizedException;
import capston2024.bustracker.exception.ResourceNotFoundException;
import capston2024.bustracker.service.AuthService;
import capston2024.bustracker.service.SchoolService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Validated
public class SchoolController {

    private final SchoolService schoolService;
    private final AuthService authService;

    @PostMapping("/admin/school")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Boolean>> createSchool(@Valid @RequestBody SchoolRegisterDTO request) {
        log.info("Creating school: {}", request.getSchoolName());
        boolean created = schoolService.createSchool(request.getSchoolName());
        return ResponseEntity.ok(new ApiResponse<>(created, "학교를 성공적으로 생성을 완료하였습니다."));
    }

    @PostMapping("/school/validation")
    public ResponseEntity<ApiResponse<Boolean>> validateSchool(@Valid @RequestBody SchoolRegisterDTO request) {
        log.info("validate school: {}", request.getSchoolName());
        boolean created = schoolService.checkBySchoolName(request.getSchoolName());
        return ResponseEntity.ok(new ApiResponse<>(created, "인증 가능한 학교입니다."));
    }

    @PostMapping("/school/mail")
    public ResponseEntity<ApiResponse<Boolean>> authenticateSchoolSendMail(@RequestBody SchoolAuthRequestDTO request) {
        Map<String, Object> sendMailObj = schoolService.sendToEmail(request.getSchoolEmail(), request.getSchoolName());

        boolean success = (boolean) sendMailObj.get("success");
        String message = (String) sendMailObj.get("message");
        int statusCode = (int) sendMailObj.get("code");

        HttpStatus httpStatus = HttpStatus.valueOf(statusCode);

        return ResponseEntity
                .status(httpStatus)
                .body(new ApiResponse<>(success, statusCode == 200 ? "인증 코드 메일을 전송하였습니다" : message));
    }

    @PostMapping("/school/code")
    public ResponseEntity<ApiResponse<Boolean>> authenticateSchool(@RequestBody SchoolAuthRequestDTO request, @AuthenticationPrincipal OAuth2User principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(false, "사용자 인증이 필요합니다."));
        }
        Map<String, Object> authenticatedObj = schoolService.authenticate(request.getSchoolEmail(), request.getSchoolName(), request.getCode());
        String message = (String) authenticatedObj.get("message");
        boolean success = (boolean) authenticatedObj.get("success");
        int statusCode = (int) authenticatedObj.get("code");

        HttpStatus httpStatus = HttpStatus.valueOf(statusCode);
        boolean isSuccess = success && authService.rankUpGuestToUser(principal, request.getSchoolName());
//        boolean isSuccess = authService.rankUpGuestToUser(principal, request.getSchoolName());
        return ResponseEntity
                .status(httpStatus)
                .body(new ApiResponse<>(isSuccess, message));
//        return ResponseEntity.ok(new ApiResponse<>(isSuccess, "인증되었습니다"));
    }


    @GetMapping("admin/school")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<String>>> getAllSchools() {
        log.info("Retrieving all schools");
        List<String> schools = schoolService.getAllSchools();
        return ResponseEntity.ok(new ApiResponse<>(schools, "모든 학교 정보를 성공적으로 반환하였습니다."));
    }

    @DeleteMapping("admin/school/{schoolName}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Boolean>> deleteSchool(@PathVariable String schoolName) {
        log.info("Deleting school: {}", schoolName);
        boolean deleted = schoolService.deleteSchool(schoolName);
        return ResponseEntity.ok(new ApiResponse<>(deleted, "해당 학교를 성공적으로 삭제하였습니다."));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Boolean>> handleGlobalException(Exception ex) {
        log.error("Unexpected error occurred: ", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiResponse<>(false, "서버 내부 오류가 발생했습니다."));
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

    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<ApiResponse<Boolean>> handleDuplicateResourceException(DuplicateResourceException ex) {
        log.error("중복된 리소스: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse<>(false, ex.getMessage()));
    }
}