package capston2024.bustracker.service;

import capston2024.bustracker.config.dto.BusArrivalEstimateResponseDTO;
import capston2024.bustracker.config.dto.KakaoDirectionsRequest;
import capston2024.bustracker.config.dto.KakaoDirectionsResponse;
import capston2024.bustracker.config.dto.KakaoPoint;
import capston2024.bustracker.domain.Bus;
import capston2024.bustracker.domain.Route;
import capston2024.bustracker.domain.Station;
import capston2024.bustracker.exception.ResourceNotFoundException;
import capston2024.bustracker.repository.BusRepository;
import capston2024.bustracker.repository.RouteRepository;
import capston2024.bustracker.repository.StationRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

// API 문서: https://developers.kakaomobility.com/docs/navi-api/directions/
@Service
@Slf4j
public class KakaoApiService {

    @Value("${KAKAO_REST_API_KEY}")
    private String REST_API_KEY;

    @Autowired
    private BusRepository busRepository;

    @Autowired
    private RouteRepository routeRepository;

    @Autowired
    private StationRepository stationRepository;

    private final RestTemplate restTemplate = new RestTemplate();

    /**
     * 다중 경유지를 포함한 남은시간 계산 API
     * @param busNumber 버스 Number
     * @param stationId 목적지 정류장 ID
     * @return 예상 소요 시간 및 경유지 정보
     */
    public BusArrivalEstimateResponseDTO getMultiWaysTimeEstimate(String busNumber, String stationId) {
        Bus bus = busRepository.findBusByBusNumber(busNumber)
                .orElseThrow(() -> new ResourceNotFoundException("존재하지 않는 버스 입니다: " + busNumber));

        Station targetStation = stationRepository.findById(stationId)
                .orElseThrow(() -> new ResourceNotFoundException("존재하지 않는 정류장 입니다: " + stationId));

        // 버스의 라우트 정보 조회
        Route route = null;
        if (bus.getRouteId() != null) {
            route = routeRepository.findById(bus.getRouteId().getId().toString())
                    .orElseThrow(() -> new ResourceNotFoundException("존재하지 않는 라우트 입니다: " + bus.getRouteId().getId()));
        } else {
            throw new ResourceNotFoundException("버스에 라우트 정보가 없습니다: " + busNumber);
        }

        // 목표 정류장의 순서 찾기
        int targetIndex = findStationIndexInRoute(route, stationId);
        log.info("targetIdx: {}", targetIndex);
        log.info("prevStationIdx: {}", bus.getPrevStationIdx());

        // 이미 지난 정류장인지 확인
        if (targetIndex <= bus.getPrevStationIdx()) {
            return BusArrivalEstimateResponseDTO.builder()
                    .estimatedTime("--분 --초")
                    .waypoints(Collections.emptyList())
                    .build();
        }

        // 현재 정류장 다음부터 목표 정류장 전까지의 정류장들을 경유지로 추출
        List<Station> waypoints = extractWaypointsFromRoute(route, bus.getPrevStationIdx(), targetIndex);
        log.info("waypoints: {}", waypoints);

        // 카카오 모빌리티 API 호출
        KakaoDirectionsResponse response = requestRouteEstimate(bus, targetStation, waypoints);
        log.info("response: {}", response);

        return BusArrivalEstimateResponseDTO.builder()
                .estimatedTime(formatDuration(response.getDuration()))
                .waypoints(waypoints.stream().map(Station::getName).collect(Collectors.toList()))
                .build();
    }

    /**
     * 라우트에서 특정 정류장의 인덱스 찾기
     */
    private int findStationIndexInRoute(Route route, String stationId) {
        for (int i = 0; i < route.getStations().size(); i++) {
            Route.RouteStation routeStation = route.getStations().get(i);
            if (routeStation.getStationId().getId().toString().equals(stationId)) {
                return i;
            }
        }
        throw new IllegalArgumentException("해당 정류장은 라우트의 경유 정류장에 포함되지 않습니다: " + stationId);
    }

    /**
     * 라우트에서 특정 구간의 정류장들을 추출
     */
    private List<Station> extractWaypointsFromRoute(Route route, int startIndex, int endIndex) {
        List<Station> waypoints = new ArrayList<>();

        // 시작 인덱스 다음부터 끝 인덱스 전까지의 정류장들만 추출
        for (int i = startIndex + 1; i < endIndex; i++) {
            Route.RouteStation routeStation = route.getStations().get(i);
            String stationRefId = routeStation.getStationId().getId().toString();
            Station station = stationRepository.findById(stationRefId)
                    .orElseThrow(() -> new ResourceNotFoundException("정류장을 찾을 수 없습니다: " + stationRefId));
            waypoints.add(station);
        }

        return waypoints;
    }

    /**
     * 경로 탐색 요청 생성 및 API 호출
     */
    private KakaoDirectionsResponse requestRouteEstimate(Bus bus, Station targetStation, List<Station> waypoints) {
        KakaoDirectionsRequest request = KakaoDirectionsRequest.builder()
                .origin(new KakaoPoint(
                        bus.getLocation().getX(), // 경도
                        bus.getLocation().getY())) // 위도
                .destination(new KakaoPoint(
                        targetStation.getLocation().getY(), // longitude
                        targetStation.getLocation().getX())) // latitude
                .waypoints(waypoints.stream()
                        .map(station -> new KakaoPoint(
                                station.getLocation().getY(), // longitude
                                station.getLocation().getX())) // latitude
                        .collect(Collectors.toList()))
                .priority("RECOMMEND")
                .build();

        return callKakaoMobilityAPI(request);
    }

    /**
     * 카카오 모빌리티 API 호출
     */
    private KakaoDirectionsResponse callKakaoMobilityAPI(KakaoDirectionsRequest request) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "KakaoAK " + REST_API_KEY);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<KakaoDirectionsRequest> entity = new HttpEntity<>(request, headers);

            ResponseEntity<KakaoDirectionsResponse> response = restTemplate.exchange(
                    "https://apis-navi.kakaomobility.com/v1/waypoints/directions",
                    HttpMethod.POST,
                    entity,
                    KakaoDirectionsResponse.class
            );

            if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null) {
                throw new RuntimeException("카카오 API에서 정보를 얻지 못하였습니다");
            }

            log.info("KAKAO API response body: {}", response.getBody());
            return response.getBody();
        } catch (Exception e) {
            log.error("카카오 API 호출 에러", e);
            throw new RuntimeException("남은 시간 계산에 실패하였습니다: " + e.getMessage(), e);
        }
    }

    /**
     * 초 단위 시간을 "분 초" 형식으로 변환
     */
    private String formatDuration(int seconds) {
        int minutes = seconds / 60;
        int remainingSeconds = seconds % 60;
        return String.format("%d분 %d초", minutes, remainingSeconds);
    }

    /**
     * 초 단위 시간을 "시간 분 초" 형식으로 변환
     */
    private String formatDurationDetailed(int seconds) {
        int hours = seconds / 3600;
        int minutes = (seconds % 3600) / 60;
        int remainingSeconds = seconds % 60;

        StringBuilder formattedTime = new StringBuilder();
        if (hours > 0) formattedTime.append(hours).append("시간 ");
        if (minutes > 0) formattedTime.append(minutes).append("분 ");
        if (remainingSeconds > 0 || formattedTime.length() == 0)
            formattedTime.append(remainingSeconds).append("초");

        return formattedTime.toString();
    }
}