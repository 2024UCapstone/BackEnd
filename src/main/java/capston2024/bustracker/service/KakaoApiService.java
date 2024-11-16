package capston2024.bustracker.service;

import capston2024.bustracker.config.dto.ArrivalTimeRequestDTO;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// API 문서: https://developers.kakaomobility.com/docs/navi-api/directions/
@Service
@Slf4j
public class KakaoApiService {

    @Value("${KAKAO_REST_API_KEY}")
    private String REST_API_KEY;

    @Autowired
    private ObjectMapper objectMapper;  // ObjectMapper 주입

    private final RestTemplate restTemplate = new RestTemplate();

    /**
     * 단일 경유지 API
     *
     * @param origin
     * @param destination
     * @return
     */
    public String getArrivalTime(ArrivalTimeRequestDTO origin, ArrivalTimeRequestDTO destination) {
        String url = "https://apis-navi.kakaomobility.com/v1/directions"
                + "?origin=" + origin.getX() + "," + origin.getY()
                + "&destination=" + destination.getX() + "," + destination.getY()
                + "&waypoints="
                + "&priority=RECOMMEND"
                + "&car_fuel=GASOLINE"
                + "&car_hipass=false"
                + "&alternatives=false"
                + "&road_details=false";
        // 헤더에 API Key 추가
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "KakaoAK " + REST_API_KEY);

        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<Map> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                entity,
                Map.class);
        // 응답 본문에서 도착 시간을 추출
        Map<String, Object> body = response.getBody();
        if (body != null) {
            List<Map<String, Object>> routes = (List<Map<String, Object>>) body.get("routes");
            if (!routes.isEmpty()) {
                Map<String, Object> summary = (Map<String, Object>) routes.get(0).get("summary");
                int duration = Integer.parseInt(summary.get("duration").toString()); // 도착 예정 시간 (초 단위)
                int hours = duration / 3600;
                int minutes = (duration % 3600) / 60;
                int seconds = duration % 60;
                StringBuilder formattedTime = new StringBuilder();
                if (hours > 0) formattedTime.append(hours).append("시간 ");
                if (minutes > 0) formattedTime.append(minutes).append("분 ");
                if (seconds > 0 || formattedTime.length() == 0) formattedTime.append(seconds).append("초"); // 0초일 때도 출력해야 하는 경우
                return formattedTime.toString();
            }
        }
        return null; // 도착 시간이 없을 때 null 반환
    }

    public String getMultiArrivalTime(Map<String, Object> request) throws JsonProcessingException {
        // 설정된 헤더에 API 키 추가
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "KakaoAK " + REST_API_KEY);
        headers.set("Content-Type", "application/json");

        // 요청 본문
        Map<String, Object> body = new HashMap<>();
        body.put("origin", request.get("origin"));
        body.put("destination", request.get("destination"));
        body.put("waypoints", request.get("waypoints"));
        body.put("priority", "RECOMMEND");
        body.put("car_fuel", "GASOLINE");
        body.put("car_hipass", false);
        body.put("alternatives", false);
        body.put("road_details", false);

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

        // API 호출
        ResponseEntity<String> response = restTemplate.exchange(
                "https://apis-navi.kakaomobility.com/v1/waypoints/directions",
                HttpMethod.POST,
                entity,
                String.class
        );

        String responseBody = response.getBody();

        // 응답에서 경로 정보 추출 및 총 소요 시간 계산
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> resultMap = objectMapper.readValue(responseBody, Map.class);

        int totalDuration = 0; // 총 소요 시간 (초 단위)

        if (resultMap != null && resultMap.containsKey("routes")) {
            List<Map<String, Object>> routes = (List<Map<String, Object>>) resultMap.get("routes");
            if (!routes.isEmpty()) {
                // 첫 번째 경로의 summary에서 소요 시간 추출
                Map<String, Object> summary = (Map<String, Object>) routes.get(0).get("summary");
                totalDuration = (Integer) summary.get("duration");
            }
        } else {
            log.error("경로를 찾을 수 없습니다.");
            return "경로를 찾을 수 없습니다.";
        }

        // 시, 분, 초 단위로 변환
        int hours = totalDuration / 3600;
        int minutes = (totalDuration % 3600) / 60;
        int seconds = totalDuration % 60;

        String formattedTime = String.format("%d시간 %d분 %d초", hours, minutes, seconds);
        log.info("총 소요 시간: {}", formattedTime);
        return formattedTime;
    }
}
