package capston2024.bustracker.controller;

import capston2024.bustracker.config.dto.ApiResponse;
import capston2024.bustracker.config.dto.StationRequestDTO;
import capston2024.bustracker.domain.Station;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.service.StationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@Slf4j
@RequestMapping("/api/station")
public class StationController {

    private final StationService stationService;

    public StationController(StationService stationService) {
        this.stationService = stationService;
    }

    // 정류장 등록
    @PostMapping
    public ResponseEntity<ApiResponse<Station>> createStation(@AuthenticationPrincipal OAuth2User user, @RequestBody StationRequestDTO createStationDTO) {
        log.info("새로운 정류장 등록 요청: {}", createStationDTO.getName());
        try {
            Station createdStation = stationService.createStation(user, createStationDTO);
            return ResponseEntity.ok(new ApiResponse<>(createdStation, "정류장이 성공적으로 등록되었습니다."));
        } catch (BusinessException e) {
            log.error("정류장 등록 실패: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiResponse<>(null, "중복된 정류장이 이미 존재합니다."));
        }
    }

    // 정류장 업데이트
    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<String>> updateStation(
            @AuthenticationPrincipal OAuth2User user,
            @PathVariable String id,
            @RequestBody StationRequestDTO stationRequestDTO) {

        log.info("{} 정류장 업데이트 요청 (ID: {})", stationRequestDTO.getName(), id);

        // 업데이트 작업 수행
        boolean result = stationService.updateStation(user, id, stationRequestDTO);

        if (result) {
            // 성공적인 업데이트 응답
            return ResponseEntity.ok(new ApiResponse<>(null, "정류장이 성공적으로 업데이트되었습니다."));
        } else {
            // 업데이트 실패 응답
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ApiResponse<>(null, "정류장 업데이트에 실패했습니다."));
        }
    }



    // 정류장 삭제
    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteStation(@PathVariable String id) {
        log.info("정류장 ID {}로 삭제 요청", id);
        stationService.deleteStation(id);
        return ResponseEntity.ok(new ApiResponse<>(null, "정류장이 성공적으로 삭제되었습니다."));
    }
}
