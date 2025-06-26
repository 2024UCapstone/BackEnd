package capston2024.bustracker.service;

import capston2024.bustracker.config.dto.RouteDTO;
import capston2024.bustracker.config.dto.RouteRequestDTO;
import capston2024.bustracker.domain.Route;
import capston2024.bustracker.domain.Station;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.exception.ErrorCode;
import capston2024.bustracker.exception.ResourceNotFoundException;
import capston2024.bustracker.repository.RouteRepository;
import capston2024.bustracker.repository.StationRepository;
import com.mongodb.DBRef;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class RouteService {

    private final RouteRepository routeRepository;
    private final StationRepository stationRepository;
    private final AuthService authService;

    /**
     * 조직별 모든 라우트 조회
     */
    public List<RouteDTO> getAllRoutesByOrganizationId(String organizationId) {
        log.info("조직 ID {}의 모든 라우트 조회", organizationId);
        if (organizationId == null || organizationId.trim().isEmpty()) {
            throw new BusinessException(ErrorCode.ACCESS_DENIED, "조직 ID가 필요합니다.");
        }
        List<Route> routes = routeRepository.findByOrganizationId(organizationId);
        return routes.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    /**
     * 특정 라우트 조회 (조직 ID 검증 포함)
     */
    public RouteDTO getRouteById(String id, String organizationId) {
        log.info("ID {}와 조직 ID {}로 라우트 조회", id, organizationId);
        if (organizationId == null || organizationId.trim().isEmpty()) {
            throw new BusinessException(ErrorCode.ACCESS_DENIED, "조직 ID가 필요합니다.");
        }

        Route route = routeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("해당 ID의 라우트를 찾을 수 없습니다: " + id));

        // 요청한 조직 ID와 라우트의 조직 ID가 일치하는지 확인
        if (!route.getOrganizationId().equals(organizationId)) {
            throw new BusinessException(ErrorCode.ACCESS_DENIED, "다른 조직의 라우트를 조회할 수 없습니다.");
        }

        return convertToDTO(route);
    }

    /**
     * 조직 내 라우트 이름으로 검색
     */
    public List<RouteDTO> searchRoutesByNameAndOrganizationId(String routeName, String organizationId) {
        log.info("조직 ID {}의 라우트 이름 {} 으로 검색", organizationId, routeName);
        if (organizationId == null || organizationId.trim().isEmpty()) {
            throw new BusinessException(ErrorCode.ACCESS_DENIED, "조직 ID가 필요합니다.");
        }

        List<Route> routes = routeRepository.findByRouteNameContainingIgnoreCaseAndOrganizationId(routeName, organizationId);
        return routes.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    /**
     * 새로운 라우트 생성
     */
    @Transactional
    public RouteDTO createRoute(OAuth2User principal, RouteRequestDTO requestDTO) {
        log.info("새로운 라우트 생성: {}", requestDTO.getRouteName());

        // 사용자 정보 및 조직 ID 가져오기
        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.trim().isEmpty()) {
            throw new BusinessException(ErrorCode.ACCESS_DENIED, "조직에 속하지 않은 사용자는 라우트를 생성할 수 없습니다.");
        }

        // 동일한 이름의 라우트가 이미 존재하는지 확인
        if (routeRepository.existsByRouteName(requestDTO.getRouteName())) {
            throw new BusinessException(ErrorCode.DUPLICATE_ENTITY, "이미 같은 이름의 라우트가 존재합니다.");
        }

        // 정류장 정보 검증 및 변환
        List<Route.RouteStation> routeStations = new ArrayList<>();
        for (RouteRequestDTO.RouteStationRequestDTO stationDTO : requestDTO.getStations()) {
            Station station = stationRepository.findById(stationDTO.getStationId())
                    .orElseThrow(() -> new ResourceNotFoundException("해당 ID의 정류장을 찾을 수 없습니다: " + stationDTO.getStationId()));

            Route.RouteStation routeStation = new Route.RouteStation(
                    stationDTO.getSequence(),
                    new DBRef("stations", station.getId())
            );
            routeStations.add(routeStation);
        }

        // 라우트 엔티티 생성
        Route route = Route.builder()
                .routeName(requestDTO.getRouteName())
                .organizationId(organizationId)
                .stations(routeStations)
                .build();

        Route savedRoute = routeRepository.save(route);
        log.info("라우트 생성 완료: ID {}", savedRoute.getId());

        return convertToDTO(savedRoute);
    }

//    /**
//     * 라우트 수정
//     */
//    @Transactional
//    public RouteDTO updateRoute(String id, OAuth2User principal, RouteRequestDTO requestDTO) {
//        log.info("라우트 ID {} 수정", id);
//
//        // 사용자 정보 및 조직 ID 가져오기
//        Map<String, Object> userInfo = authService.getUserDetails(principal);
//        String organizationId = (String) userInfo.get("organizationId");
//
//        // 수정할 라우트 조회
//        Route route = routeRepository.findById(id)
//                .orElseThrow(() -> new ResourceNotFoundException("해당 ID의 라우트를 찾을 수 없습니다: " + id));
//
//        // 요청한 사용자의 조직 ID와 라우트의 조직 ID가 일치하는지 확인
//        if (!route.getOrganizationId().equals(organizationId)) {
//            throw new BusinessException(ErrorCode.ACCESS_DENIED, "다른 조직의 라우트를 수정할 수 없습니다.");
//        }
//
//        // 라우트 이름 수정
//        if (requestDTO.getRouteName() != null && !requestDTO.getRouteName().equals(route.getRouteName())) {
//            // 변경할 이름이 이미 존재하는지 확인
//            routeRepository.findByOrganizationIdAndRouteName(organizationId, requestDTO.getRouteName())
//                    .ifPresent(existingRoute -> {
//                        if (!existingRoute.getId().equals(id)) {
//                            throw new BusinessException(ErrorCode.DUPLICATE_ENTITY, "이미 같은 이름의 라우트가 존재합니다.");
//                        }
//                    });
//            route.setRouteName(requestDTO.getRouteName());
//        }
//
//        // 정류장 정보 업데이트
//        if (requestDTO.getStations() != null) {
//            List<Route.RouteStation> routeStations = new ArrayList<>();
//            for (RouteRequestDTO.RouteStationRequestDTO stationDTO : requestDTO.getStations()) {
//                Station station = stationRepository.findById(stationDTO.getStationId())
//                        .orElseThrow(() -> new ResourceNotFoundException("해당 ID의 정류장을 찾을 수 없습니다: " + stationDTO.getStationId()));
//
//                Route.RouteStation routeStation = new Route.RouteStation(
//                        stationDTO.getSequence(),
//                        new DBRef("stations", station.getId())
//                );
//                routeStations.add(routeStation);
//            }
//            route.setStations(routeStations);
//        }
//
//        Route updatedRoute = routeRepository.save(route);
//        log.info("라우트 수정 완료: ID {}", updatedRoute.getId());
//
//        return convertToDTO(updatedRoute);
//    }

    /**
     * 라우트 이름과 조직 ID로 라우트 수정
     */
    @Transactional
    public RouteDTO updateRouteByNameAndOrganizationId(String routeName, String organizationId, RouteRequestDTO requestDTO) {
        log.info("라우트 이름 {} 및 조직 ID {} 기준으로 수정", routeName, organizationId);

        // 라우트 이름과 조직 ID로 라우트 조회
        Route route = routeRepository.findByRouteNameAndOrganizationId(routeName, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException("해당 이름과 조직에 속한 라우트를 찾을 수 없습니다: " + routeName));

        // 정류장 정보 업데이트
        if (requestDTO.getStations() != null) {
            List<Route.RouteStation> routeStations = new ArrayList<>();
            for (RouteRequestDTO.RouteStationRequestDTO stationDTO : requestDTO.getStations()) {
                Station station = stationRepository.findById(stationDTO.getStationId())
                        .orElseThrow(() -> new ResourceNotFoundException("해당 ID의 정류장을 찾을 수 없습니다: " + stationDTO.getStationId()));

                Route.RouteStation routeStation = new Route.RouteStation(
                        stationDTO.getSequence(),
                        new DBRef("stations", station.getId())
                );
                routeStations.add(routeStation);
            }
            route.setStations(routeStations);
        }

        // 새 이름이 있으면 이름도 업데이트
        if (requestDTO.getRouteName() != null && !requestDTO.getRouteName().equals(routeName)) {
            // 변경할 이름이 이미 존재하는지 확인
            routeRepository.findByRouteNameAndOrganizationId(requestDTO.getRouteName(), organizationId)
                    .ifPresent(existingRoute -> {
                        throw new BusinessException(ErrorCode.DUPLICATE_ENTITY, "이미 같은 이름의 라우트가 존재합니다.");
                    });
            route.setRouteName(requestDTO.getRouteName());
        }

        Route updatedRoute = routeRepository.save(route);
        log.info("라우트 수정 완료: 이름 {}", updatedRoute.getRouteName());

        return convertToDTO(updatedRoute);
    }

    /**
     * 라우트 삭제
     */
    @Transactional
    public void deleteRoute(String id, OAuth2User principal) {
        log.info("라우트 ID {} 삭제", id);

        // 사용자 정보 및 조직 ID 가져오기
        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        // 삭제할 라우트 조회
        Route route = routeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("해당 ID의 라우트를 찾을 수 없습니다: " + id));

        // 요청한 사용자의 조직 ID와 라우트의 조직 ID가 일치하는지 확인
        if (!route.getOrganizationId().equals(organizationId)) {
            throw new BusinessException(ErrorCode.ACCESS_DENIED, "다른 조직의 라우트를 삭제할 수 없습니다.");
        }

        routeRepository.delete(route);
        log.info("라우트 삭제 완료: ID {}", id);
    }

    /**
     * Route 엔티티를 RouteDTO로 변환
     */
    private RouteDTO convertToDTO(Route route) {
        List<RouteDTO.RouteStationDTO> stationDTOs = new ArrayList<>();

        for (Route.RouteStation routeStation : route.getStations()) {
            String stationId = routeStation.getStationId().getId().toString();

            // 정류장 정보 조회
            String stationName = "알 수 없음";
            try {
                Station station = stationRepository.findById(stationId).orElse(null);
                if (station != null) {
                    stationName = station.getName();
                }
            } catch (Exception e) {
                log.warn("정류장 정보 조회 실패: {}", stationId, e);
            }

            RouteDTO.RouteStationDTO stationDTO = new RouteDTO.RouteStationDTO(
                    routeStation.getSequence(),
                    stationId,
                    stationName
            );
            stationDTOs.add(stationDTO);
        }

        return new RouteDTO(
                route.getId(),
                route.getRouteName(),
                route.getOrganizationId(),
                stationDTOs
        );
    }

}