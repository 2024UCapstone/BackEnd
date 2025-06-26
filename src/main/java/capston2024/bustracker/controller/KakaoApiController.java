package capston2024.bustracker.controller;

import capston2024.bustracker.config.dto.ApiResponse;
import capston2024.bustracker.config.dto.BusArrivalEstimateResponseDTO;
import capston2024.bustracker.exception.ResourceNotFoundException;
import capston2024.bustracker.service.KakaoApiService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api/kakao-api")
@Tag(name = "Kakao API", description = "카카오 API 통합 서비스")
public class KakaoApiController {

    private final KakaoApiService kakaoApiService;

    /**
     * 버스 도착 예정 시간 조회
     */
    @GetMapping("/arrival-time/multi")
    @Operation(summary = "버스 도착 예정 시간 조회",
            description = "특정 버스가 특정 정류장에 도착하는 예정 시간을 다중 경유지를 고려하여 계산합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "도착 예정 시간 조회 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "버스 또는 정류장을 찾을 수 없음"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "500", description = "카카오 API 오류")
    })
    public ResponseEntity<ApiResponse<BusArrivalEstimateResponseDTO>> getTimeEstimate(
            @Parameter(description = "버스 ID", required = true, example = "BUS001") @RequestParam String busId,
            @Parameter(description = "정류장 ID", required = true, example = "STATION001") @RequestParam String stationId) {

        log.info("버스 도착 예정 시간 조회 요청 - 버스 ID: {}, 정류장 ID: {}", busId, stationId);

        BusArrivalEstimateResponseDTO result = kakaoApiService.getMultiWaysTimeEstimate(busId, stationId);
        log.info("다중 도착예정 처리 결과 : {}", result);

        return ResponseEntity.ok(new ApiResponse<>(result, "다중 도착예정시간이 성공적으로 조회되었습니다."));
    }

    /**
     * 리소스 찾을 수 없음 예외 처리
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Boolean>> handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.error("찾을 수 없는 리소스: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiResponse<>(false, ex.getMessage()));
    }

    /**
     * 일반 예외 처리
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneralException(Exception ex) {
        log.error("카카오 API 처리 중 예외 발생: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiResponse<>(null, "카카오 API 처리 중 오류가 발생했습니다."));
    }
}