package capston2024.bustracker.service;

import capston2024.bustracker.config.dto.*;
import capston2024.bustracker.domain.Bus;
import capston2024.bustracker.domain.Route;
import capston2024.bustracker.domain.Station;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.exception.ResourceNotFoundException;
import capston2024.bustracker.repository.BusRepository;
import capston2024.bustracker.repository.RouteRepository;
import capston2024.bustracker.repository.StationRepository;
import capston2024.bustracker.util.BusNumberGenerator;
import com.mongodb.DBRef;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class BusService {

    private final BusRepository busRepository;
    private final RouteRepository routeRepository;
    private final StationRepository stationRepository;
    private final BusNumberGenerator busNumberGenerator;
    private final KakaoApiService kakaoApiService;
    private final ApplicationEventPublisher eventPublisher;

    /**
     * 버스 상태 업데이트 이벤트 Record
     */
    public record BusStatusUpdateEvent(String organizationId, BusRealTimeStatusDTO busStatus) {
    }

    /**
     * 버스 등록
     */
    @Transactional
    public String createBus(BusRegisterDTO busRegisterDTO, String organizationId) {
        Route route = routeRepository.findById(busRegisterDTO.getRouteId())
                .orElseThrow(() -> new ResourceNotFoundException("존재하지 않는 노선입니다: " + busRegisterDTO.getRouteId()));

        if (!route.getOrganizationId().equals(organizationId)) {
            throw new BusinessException("다른 조직의 노선에 버스를 등록할 수 없습니다.");
        }

        Bus bus = Bus.builder()
                .organizationId(organizationId)
                .busRealNumber(busRegisterDTO.getBusRealNumber() != null ? busRegisterDTO.getBusRealNumber().trim() : null)
                .totalSeats(busRegisterDTO.getTotalSeats())
                .occupiedSeats(0)
                .availableSeats(busRegisterDTO.getTotalSeats())
                .location(new GeoJsonPoint(0, 0))
                .routeId(new DBRef("routes", route.getId()))
                .timestamp(Instant.now())
                .prevStationIdx(0)
                .isOperate(busRegisterDTO.isOperate())
                .build();

        bus = busRepository.save(bus);

        String busNumber = busNumberGenerator.generateBusNumber(bus.getId(), organizationId);
        List<String> existingBusNumbers = getAllBusesByOrganizationId(organizationId).stream()
                .map(Bus::getBusNumber).filter(Objects::nonNull).collect(Collectors.toList());

        int attempts = 0;
        while (!busNumberGenerator.isUniqueInOrganization(busNumber, existingBusNumbers) && attempts < 10) {
            busNumber = busNumberGenerator.generateBusNumber(bus.getId() + attempts, organizationId);
            attempts++;
        }

        if (!busNumberGenerator.isUniqueInOrganization(busNumber, existingBusNumbers)) {
            throw new BusinessException("고유한 버스 번호를 생성할 수 없습니다.");
        }

        bus.setBusNumber(busNumber);
        busRepository.save(bus);

        // 버스 상태 업데이트 이벤트 발행
        broadcastBusStatusUpdate(bus);

        return busNumber;
    }

    /**
     * 버스 상태 업데이트 이벤트를 발행합니다.
     * @param bus 업데이트된 버스 객체
     */
    private void broadcastBusStatusUpdate(Bus bus) {
        BusRealTimeStatusDTO statusDTO = convertToStatusDTO(bus);
        eventPublisher.publishEvent(new BusStatusUpdateEvent(bus.getOrganizationId(), statusDTO));
    }


    /**
     * 버스 삭제
     */
    @Transactional
    public boolean removeBus(String busNumber, String organizationId) {
        Bus bus = getBusByNumberAndOrganization(busNumber, organizationId);
        busRepository.delete(bus);
        return true;
    }

    /**
     * 버스 수정
     */
    @Transactional
    public boolean modifyBus(BusInfoUpdateDTO busInfoUpdateDTO, String organizationId) {
        if (busInfoUpdateDTO.getTotalSeats() < 0) {
            throw new IllegalArgumentException("전체 좌석 수는 0보다 작을 수 없습니다.");
        }

        Bus bus = getBusByNumberAndOrganization(busInfoUpdateDTO.getBusNumber(), organizationId);

        if (busInfoUpdateDTO.getBusRealNumber() != null) {
            bus.setBusRealNumber(busInfoUpdateDTO.getBusRealNumber().trim());
        }

        if (busInfoUpdateDTO.getIsOperate() != null) {
            bus.setOperate(busInfoUpdateDTO.getIsOperate());
        }

        if (busInfoUpdateDTO.getRouteId() != null && !busInfoUpdateDTO.getRouteId().equals(bus.getRouteId().getId().toString())) {
            Route route = routeRepository.findById(busInfoUpdateDTO.getRouteId())
                    .orElseThrow(() -> new ResourceNotFoundException("존재하지 않는 노선입니다: " + busInfoUpdateDTO.getRouteId()));
            if (!route.getOrganizationId().equals(organizationId)) {
                throw new BusinessException("다른 조직의 노선으로 변경할 수 없습니다.");
            }
            bus.setRouteId(new DBRef("routes", route.getId()));
            bus.setPrevStationIdx(0);
            bus.setPrevStationId(null);
            bus.setLastStationTime(null);
        }

        bus.setTotalSeats(busInfoUpdateDTO.getTotalSeats());
        int occupiedSeats = bus.getOccupiedSeats();
        if (occupiedSeats > busInfoUpdateDTO.getTotalSeats()) {
            occupiedSeats = busInfoUpdateDTO.getTotalSeats();
            bus.setOccupiedSeats(occupiedSeats);
        }
        bus.setAvailableSeats(busInfoUpdateDTO.getTotalSeats() - occupiedSeats);

        busRepository.save(bus);

        // 버스 상태 업데이트 이벤트 발행
        broadcastBusStatusUpdate(bus);

        return true;
    }

    /**
     * 버스의 모든 정류장 상세 정보 조회
     */
    public List<Station> getBusStationsDetail(String busNumber, String organizationId) {
        Bus bus = getBusByNumberAndOrganization(busNumber, organizationId);
        if (bus.getRouteId() == null) {
            throw new BusinessException("버스에 할당된 노선이 없습니다.");
        }
        String routeId = bus.getRouteId().getId().toString();
        Route route = routeRepository.findById(routeId)
                .orElseThrow(() -> new ResourceNotFoundException("해당 ID의 노선을 찾을 수 없습니다: " + routeId));

        if (!route.getOrganizationId().equals(organizationId)) {
            throw new BusinessException("다른 조직의 라우트 정보에 접근할 수 없습니다.");
        }

        List<String> stationIds = route.getStations().stream()
                .map(routeStation -> routeStation.getStationId().getId().toString())
                .collect(Collectors.toList());

        Map<String, Station> stationMap = stationRepository.findAllByIdIn(stationIds).stream()
                .collect(Collectors.toMap(Station::getId, station -> station));

        List<Station> resultStations = new ArrayList<>();
        String currentStationId = null;

        for (int i = 0; i < route.getStations().size(); i++) {
            Route.RouteStation routeStation = route.getStations().get(i);
            String stationId = routeStation.getStationId().getId().toString();
            Station station = stationMap.get(stationId);
            if (station == null) continue;

            station.setSequence(i);
            station.setPassed(i <= bus.getPrevStationIdx());
            station.setCurrentStation(i == bus.getPrevStationIdx() + 1);

            if (station.isCurrentStation()) {
                currentStationId = stationId;
            }
            resultStations.add(station);
        }

        if (currentStationId != null) {
            try {
                BusArrivalEstimateResponseDTO arrivalTime = kakaoApiService.getMultiWaysTimeEstimate(bus.getBusNumber(), currentStationId);
                resultStations.stream()
                        .filter(Station::isCurrentStation)
                        .findFirst()
                        .ifPresent(station -> station.setEstimatedArrivalTime(arrivalTime.getEstimatedTime()));
            } catch (Exception e) {
                log.warn("도착 시간 예측 실패: {}", e.getMessage());
            }
        }
        return resultStations;
    }

    // Getter 및 유틸리티 메소드들

    public Bus getBusByNumberAndOrganization(String busNumber, String organizationId) {
        return busRepository.findByBusNumberAndOrganizationId(busNumber, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException(String.format("버스를 찾을 수 없습니다: 번호=%s, 조직=%s", busNumber, organizationId)));
    }

    /**
     * 실제 버스 번호와 조직으로 특정 버스 조회
     */
    public Bus getBusByRealNumberAndOrganization(String busRealNumber, String organizationId) {
        return busRepository.findByBusRealNumberAndOrganizationId(busRealNumber, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        String.format("실제 버스 번호로 버스를 찾을 수 없습니다: 실제번호=%s, 조직=%s", busRealNumber, organizationId)));
    }


    public List<Bus> getAllBusesByOrganizationId(String organizationId) {
        return busRepository.findByOrganizationId(organizationId);
    }

    public List<BusRealTimeStatusDTO> getAllBusStatusByOrganizationId(String organizationId) {
        return getAllBusesByOrganizationId(organizationId).stream()
                .map(this::convertToStatusDTO)
                .collect(Collectors.toList());
    }

    public LocationDTO getBusLocationByBusNumber(String busNumber, String organizationId) {
        Bus bus = getBusByNumberAndOrganization(busNumber, organizationId);
        LocationDTO locationDTO = new LocationDTO();
        if (bus.getLocation() != null) {
            locationDTO.setLatitude(bus.getLocation().getY());
            locationDTO.setLongitude(bus.getLocation().getX());
        }
        locationDTO.setTimestamp(bus.getTimestamp());
        return locationDTO;
    }

    public BusSeatDTO getBusSeatsByBusNumber(String busNumber, String organizationId) {
        Bus bus = getBusByNumberAndOrganization(busNumber, organizationId);
        BusSeatDTO busSeatDTO = new BusSeatDTO();
        busSeatDTO.setBusNumber(bus.getBusNumber());
        busSeatDTO.setBusRealNumber(bus.getBusRealNumber());
        busSeatDTO.setAvailableSeats(bus.getAvailableSeats());
        busSeatDTO.setOccupiedSeats(bus.getOccupiedSeats());
        busSeatDTO.setTotalSeats(bus.getTotalSeats());
        busSeatDTO.setOperate(bus.isOperate());
        return busSeatDTO;
    }

    /**
     * 운행 중인 버스만 조회
     */
    public List<BusRealTimeStatusDTO> getOperatingBusesByOrganizationId(String organizationId) {
        List<Bus> operatingBuses = busRepository.findByOrganizationIdAndIsOperateTrue(organizationId);
        return operatingBuses.stream()
                .map(this::convertToStatusDTO)
                .collect(Collectors.toList());
    }

    /**
     * 특정 정류장을 경유하는 조직의 모든 버스 조회
     */
    public List<BusRealTimeStatusDTO> getBusesByStationAndOrganization(String stationId, String organizationId) {
        log.info("특정 정류장을 경유하는 버스 조회 - 정류장 ID: {}, 조직 ID: {}", stationId, organizationId);

        List<Bus> organizationBuses = getAllBusesByOrganizationId(organizationId);
        List<BusRealTimeStatusDTO> result = new ArrayList<>();

        for (Bus bus : organizationBuses) {
            if (bus.getRouteId() == null) continue;

            String routeId = bus.getRouteId().getId().toString();
            Route route = routeRepository.findById(routeId).orElse(null);

            if (route != null && route.getStations() != null) {
                boolean containsStation = route.getStations().stream()
                        .anyMatch(routeStation -> routeStation.getStationId().getId().toString().equals(stationId));

                if (containsStation) {
                    result.add(convertToStatusDTO(bus));
                }
            }
        }
        log.info("정류장 {} 경유 버스 {} 대 조회됨", stationId, result.size());
        return result;
    }


    private BusRealTimeStatusDTO convertToStatusDTO(Bus bus) {
        Route route = (bus.getRouteId() != null) ? routeRepository.findById(bus.getRouteId().getId().toString()).orElse(null) : null;
        String routeName = (route != null) ? route.getRouteName() : "알 수 없음";
        int totalStations = (route != null && route.getStations() != null) ? route.getStations().size() : 0;
        Station currentStation = (bus.getPrevStationId() != null) ? stationRepository.findById(bus.getPrevStationId()).orElse(null) : null;
        String currentStationName = (currentStation != null) ? currentStation.getName() : "알 수 없음";

        return new BusRealTimeStatusDTO(
                bus.getId(),
                bus.getBusNumber(),
                bus.getBusRealNumber(),
                routeName,
                bus.getOrganizationId(),
                bus.getLocation() != null ? bus.getLocation().getY() : 0,
                bus.getLocation() != null ? bus.getLocation().getX() : 0,
                bus.getTotalSeats(),
                bus.getOccupiedSeats(),
                bus.getAvailableSeats(),
                currentStationName,
                bus.getTimestamp() != null ? bus.getTimestamp().toEpochMilli() : 0,
                bus.getPrevStationIdx(),
                totalStations,
                bus.isOperate()
        );
    }
}