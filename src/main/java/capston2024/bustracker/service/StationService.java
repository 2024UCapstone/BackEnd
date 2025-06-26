package capston2024.bustracker.service;

import capston2024.bustracker.config.dto.RouteDTO;
import capston2024.bustracker.config.dto.StationRequestDTO;
import capston2024.bustracker.domain.Bus;
import capston2024.bustracker.domain.Route;
import capston2024.bustracker.domain.Station;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.exception.ErrorCode;
import capston2024.bustracker.exception.ResourceNotFoundException;
import capston2024.bustracker.repository.BusRepository;
import capston2024.bustracker.repository.RouteRepository;
import capston2024.bustracker.repository.StationRepository;
import com.mongodb.DBRef;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class StationService {

    private final StationRepository stationRepository;
    private final RouteRepository routeRepository;


    // 정류장 이름으로 검색
    public List<Station> searchStationsByNameAndOrganizationId(String stationName, String organizationId) {
        log.info("{}의 조직 id로 {} 정류장을 찾는 중입니다....", organizationId, stationName);
        if (organizationId == null || organizationId.trim().isEmpty()) {
            throw new BusinessException(ErrorCode.ACCESS_DENIED, "조직 ID가 필요합니다.");
        }

        return stationRepository.findByNameContainingIgnoreCaseAndOrganizationId(stationName, organizationId);
    }

    // 모든 정류장 조회
    public List<Station> getAllStations(String organizationId) {
        log.info("모든 정류장을 불러들이는 중...");
        return stationRepository.findAllByOrganizationId(organizationId);
    }

    // 특정 ID로 정류장 조회
    public Station getStationById(String id) {
        log.info("ID {}로 정류장을 찾는 중입니다....", id);
        return stationRepository.findById(id)
                .orElseThrow(() -> new BusinessException(ErrorCode.ENTITY_NOT_FOUND));
    }

    // 새로운 정류장 추가
    public Station createStation(String organizationId, StationRequestDTO createStationDTO) {
        log.info("새로운 정류장 추가 중: {}", createStationDTO.getName());

        // 중복된 정류장이 있는지 확인
        if (stationRepository.findByNameAndOrganizationId(createStationDTO.getName(), organizationId).isPresent()) {
            throw new BusinessException(ErrorCode.DUPLICATE_ENTITY, "이미 존재하는 정류장입니다.");
        }

        // 새로운 정류장 생성
        Station newStation = Station.builder()
                .name(createStationDTO.getName())
                .location(new GeoJsonPoint(createStationDTO.getLatitude(), createStationDTO.getLongitude()))
                .organizationId(organizationId) // 사용자 소속 정보 추가
                .build();

        return stationRepository.save(newStation);
    }

    // 정류장 업데이트 - 유효성 검사 포함
    public boolean updateStation(String organizationId, String stationId, StationRequestDTO stationRequestDTO) {
        log.info("{} 정류장 업데이트 중...", stationRequestDTO.getName());

        try {
            // 업데이트할 정류장을 ID로 찾기
            Station existingStation = stationRepository.findById(stationId)
                    .orElseThrow(() -> new BusinessException(ErrorCode.ENTITY_NOT_FOUND, "해당 ID의 정류장을 찾을 수 없습니다."));

            // 정류장 정보 업데이트
            existingStation.setName(stationRequestDTO.getName());
            existingStation.setLocation(new GeoJsonPoint(stationRequestDTO.getLatitude(), stationRequestDTO.getLongitude()));
            existingStation.setOrganizationId(organizationId);

            // 변경된 정보를 데이터베이스에 저장
            Station savedStation = stationRepository.save(existingStation);

            // 저장 결과 확인
            if (savedStation != null && savedStation.getId() != null) {
                log.info("정류장 업데이트 완료: {}", savedStation.getName());
                return true;
            } else {
                log.error("정류장 저장 실패");
                return false;
            }

        } catch (BusinessException e) {
            log.error("정류장 업데이트 중 오류 발생 (비즈니스 예외): {}", e.getMessage());
            throw e;  // 비즈니스 예외는 상위로 전파하여 적절한 처리 가능하도록 함
        } catch (Exception e) {
            log.error("정류장 업데이트 중 시스템 오류 발생: {}", e.getMessage());
            throw new BusinessException(ErrorCode.GENERAL_ERROR, "정류장 업데이트 중 오류가 발생했습니다.");
        }
    }


    // 정류장 삭제
    public void deleteStation(String id) {
        log.info("ID {}로 정류장 삭제 중...", id);
        Station station = getStationById(id);  // 존재 여부 확인

        // 각 노선에서 해당 정류장을 제거
        List<Route> routesWithStation = routeRepository.findByStationsStationId(new DBRef("stations", id));

        for (Route route : routesWithStation) {
            // RouteStation 리스트에서 stationId의 id가 삭제할 정류장의 id와 일치하는 항목 제거
            route.getStations().removeIf(routeStation ->
                    routeStation.getStationId().getId().toString().equals(id));

            // 남은 정류장들의 순서(sequence) 재정렬
            int sequenceCounter = 1;
            for (Route.RouteStation routeStation : route.getStations()) {
                routeStation.setSequence(sequenceCounter++);
            }

            routeRepository.save(route); // 변경사항 저장
            log.info("노선 {}에서 정류장 {}가 삭제되었습니다.", route.getRouteName(), id);
        }

        // 정류장 삭제
        stationRepository.delete(station);
        log.info("정류장 {}가 삭제되었습니다.", id);
    }
}
