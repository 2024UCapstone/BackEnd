package capston2024.bustracker.controller;

import capston2024.bustracker.config.dto.ApiResponse;
import capston2024.bustracker.config.dto.ArrivalTimeRequestDTO;
import capston2024.bustracker.config.dto.ArrivalTimeResponseDTO;
import capston2024.bustracker.service.KakaoApiService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api/kakao-api")
public class KakaoApiController {

    private final KakaoApiService kakaoApiService;
    @Autowired
    private ObjectMapper objectMapper;

    @GetMapping("/arrival-time/single")
    public ResponseEntity<ApiResponse<ArrivalTimeResponseDTO>> getSingleArrivalTime(
            @RequestParam String origin,
            @RequestParam String destination) {
        log.info("도착 예정 시간을 요청 받았습니다. 출발지: {}, 목적지: {}", origin, destination);
        String[] origins = origin.split(",");
        ArrivalTimeRequestDTO originDTO = new ArrivalTimeRequestDTO(origins[0], Double.parseDouble(origins[1]), Double.parseDouble(origins[2]));
        String[] destinations = destination.split(",");
        ArrivalTimeRequestDTO destinationDTO = new ArrivalTimeRequestDTO(destinations[0], Double.parseDouble(destinations[1]), Double.parseDouble(destinations[2]));
        String arrivalTimeInSeconds = kakaoApiService.getArrivalTime(originDTO, destinationDTO);
        return ResponseEntity.ok(new ApiResponse<>(new ArrivalTimeResponseDTO(originDTO.getName(), arrivalTimeInSeconds), "도착예정시간이 성공적으로 조회되었습니다."));
    }

    @PostMapping("/arrival-time/multi")
    public ResponseEntity<String> getMultiArrivalTime(@RequestBody Map<String, Object> request) {
        try {
            String result = kakaoApiService.getMultiArrivalTime(request);

            log.info("API 응답: " + result); // 응답 내용 -> 로그 표시

            // 응답이 JSON이 아닌 경우, 그대로 반환
            if (!result.trim().startsWith("{") && !result.trim().startsWith("[")) {
                return ResponseEntity.status(HttpStatus.OK).body(result);
            }

            // 응답을 JSON으로 변환
            Map<String, Object> resultMap = objectMapper.readValue(result, Map.class);

            // routes 배열이 비어있는지 체크
            List<Map<String, Object>> routes = (List<Map<String, Object>>) resultMap.get("routes");
            if (routes == null || routes.isEmpty()) {
                log.error("길찾기 실패: routes 배열이 비어있습니다.");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("길찾기 실패: routes 배열이 비어있습니다.");
            }

            // 첫 번째 route의 result_code와 summary 가져오기
            Map<String, Object> firstRoute = routes.get(0);
            Integer resultCode = (Integer) firstRoute.get("result_code");
            String resultMsg = (String) firstRoute.get("result_msg");

            // 성공 시 소요 시간 계산
            if (resultCode == 0) {
                log.info("길찾기 성공");

                Map<String, Object> summary = (Map<String, Object>) firstRoute.get("summary");
                if (summary == null || !summary.containsKey("duration")) {
                    log.error("길찾기 실패: summary에 duration 정보가 없습니다.");
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body("길찾기 실패: summary에 duration 정보가 없습니다.");
                }

                Integer totalDuration = (Integer) summary.get("duration");

                // 시, 분, 초로 변환
                int hours = totalDuration / 3600;
                int minutes = (totalDuration % 3600) / 60;
                int seconds = totalDuration % 60;

                String formattedTime = String.format("총 소요 시간: %d시간 %d분 %d초", hours, minutes, seconds);
                return ResponseEntity.status(HttpStatus.OK).body(formattedTime);

            } else {
                log.error("길찾기 실패: " + resultMsg);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("길찾기 실패: " + resultMsg);
            }

        } catch (JsonProcessingException e) {
            log.error("JSON 파싱 오류: " + e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("JSON 파싱 중 오류가 발생했습니다.");
        } catch (Exception e) {
            log.error("예기치 않은 오류 발생: " + e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("예기치 않은 오류가 발생했습니다.");
        }
    }


}
