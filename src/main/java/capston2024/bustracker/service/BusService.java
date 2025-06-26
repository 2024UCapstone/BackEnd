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
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class BusService {
    private static final double STATION_RADIUS = 120.0; // 120미터 반경으로 직접 설정

    private final BusRepository busRepository;
    private final RouteRepository routeRepository;
    private final StationRepository stationRepository;
    private final MongoOperations mongoOperations;
    private final BusNumberGenerator busNumberGenerator;
    private final ApplicationEventPublisher eventPublisher;
    private final KakaoApiService kakaoApiService;

    // 버스 위치 업데이트 큐
    private final Map<String, BusRealTimeLocationDTO> pendingLocationUpdates = new ConcurrentHashMap<>();
    private ApplicationContext applicationContext;

    public CompletionStage<Void> processBusLocationAsync(String csvData) {
        return CompletableFuture.runAsync(() -> {
            try {
                BusRealTimeLocationDTO update = parseCsvToBusUpdate(csvData);
                log.info("새로운 업데이트 수신: {}", update);
                pendingLocationUpdates.compute(update.getBusNumber(), (key, existing) -> {
                    if (existing == null || update.getTimestamp().isAfter(existing.getTimestamp())) {
                        log.info("업데이트 대기열에 추가: {}", update);
                        return update;
                    }
                    return existing;
                });
            } catch (Exception e) {
                log.error("버스 위치 처리 중 오류 발생: ", e);
            }
        });
    }

    private BusRealTimeLocationDTO parseCsvToBusUpdate(String csvData) {
        String[] parts = csvData.split(",");
        if (parts.length != 5) {
            throw new IllegalArgumentException("CSV 형식이 알맞지 않습니다. 형식: 버스번호,조직코드,위도,경도,좌석수");
        }

        String busNumber = parts[0];
        String organizationId = parts[1];
        double latitude = Double.parseDouble(parts[2]);
        double longitude = Double.parseDouble(parts[3]);
        int occupiedSeats = Integer.parseInt(parts[4]);
        Instant timestamp = Instant.now();

        return new BusRealTimeLocationDTO(busNumber, organizationId, new GeoJsonPoint(latitude, longitude), occupiedSeats, timestamp);
    }

    /**
     * 버스 상태 업데이트 이벤트
     */
    public record BusStatusUpdateEvent(String organizationId, BusRealTimeStatusDTO busStatus) {
    }

    /**
     * 버스 등록
     */
    @Transactional
    public String createBus(BusRegisterDTO busRegisterDTO, String organizationId) {
        // 노선 존재 확인
        Route route = routeRepository.findById(busRegisterDTO.getRouteId())
                .orElseThrow(() -> new ResourceNotFoundException("존재하지 않는 노선입니다: " + busRegisterDTO.getRouteId()));

        // 요청한 조직과 노선의 조직이 일치하는지 확인
        if (!route.getOrganizationId().equals(organizationId)) {
            throw new BusinessException("다른 조직의 노선에 버스를 등록할 수 없습니다.");
        }

        // 새 버스 생성 (ID는 MongoDB가 자동 생성)
        Bus bus = Bus.builder()
                .organizationId(organizationId)
                .busRealNumber(busRegisterDTO.getBusRealNumber() != null ?
                        busRegisterDTO.getBusRealNumber().trim() : null)
                .totalSeats(busRegisterDTO.getTotalSeats())
                .occupiedSeats(0)
                .availableSeats(busRegisterDTO.getTotalSeats())
                .location(new GeoJsonPoint(0, 0)) // 초기 위치
                .routeId(new DBRef("routes", route.getId()))
                .timestamp(Instant.now())
                .prevStationIdx(0) // 초기값은 첫 번째 정류장
                .isOperate(busRegisterDTO.isOperate()) // 운행 여부 설정
                .build();

        // 저장하여 ID 획득
        bus = busRepository.save(bus);

        // 버스 ID에서 고유한 버스 번호 생성
        String busNumber = busNumberGenerator.generateBusNumber(bus.getId(), organizationId);

        // 해당 조직의 모든 버스 번호 조회
        List<String> existingBusNumbers = getAllBusesByOrganizationId(organizationId)
                .stream()
                .map(Bus::getBusNumber)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        // 번호가 중복되는 경우 재생성 (최대 10회 시도)
        int attempts = 0;
        while (!busNumberGenerator.isUniqueInOrganization(busNumber, existingBusNumbers) && attempts < 10) {
            busNumber = busNumberGenerator.generateBusNumber(bus.getId() + attempts, organizationId);
            attempts++;
        }

        if (!busNumberGenerator.isUniqueInOrganization(busNumber, existingBusNumbers)) {
            throw new BusinessException("고유한 버스 번호를 생성할 수 없습니다. 나중에 다시 시도해 주세요.");
        }

        // 버스 번호 업데이트
        bus.setBusNumber(busNumber);
        busRepository.save(bus);

        log.info("새로운 버스가 등록되었습니다: ID={}, 번호={}, 실제 버스번호={}, 조직={}, 운행여부={}",
                bus.getId(), busNumber, bus.getBusRealNumber(), organizationId, bus.isOperate());

        // 버스 등록 후 상태 업데이트 이벤트 발생
        broadcastBusStatusUpdate(bus);

        return busNumber;
    }

    /**
     * 버스 삭제
     */
    @Transactional
    public boolean removeBus(String busNumber, String organizationId) {
        Bus bus = getBusByNumberAndOrganization(busNumber, organizationId);
        busRepository.delete(bus);
        log.info("버스가 삭제되었습니다: 번호={}, 실제번호={}, 조직={}",
                busNumber, bus.getBusRealNumber(), organizationId);
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

        // 버스 존재 확인
        Bus bus = getBusByNumberAndOrganization(busInfoUpdateDTO.getBusNumber(), organizationId);

        // 실제 버스 번호 수정
        if (busInfoUpdateDTO.getBusRealNumber() != null) {
            String newRealNumber = busInfoUpdateDTO.getBusRealNumber().trim();
            bus.setBusRealNumber(newRealNumber.isEmpty() ? null : newRealNumber);
        }

        // 운행 여부 수정
        if (busInfoUpdateDTO.getIsOperate() != null) {
            bus.setOperate(busInfoUpdateDTO.getIsOperate());
        }

        // 노선 변경이 있는 경우
        if (busInfoUpdateDTO.getRouteId() != null &&
                !busInfoUpdateDTO.getRouteId().equals(bus.getRouteId().getId().toString())) {

            Route route = routeRepository.findById(busInfoUpdateDTO.getRouteId())
                    .orElseThrow(() -> new ResourceNotFoundException("존재하지 않는 노선입니다: " + busInfoUpdateDTO.getRouteId()));

            // 같은 조직의 노선인지 확인
            if (!route.getOrganizationId().equals(organizationId)) {
                throw new BusinessException("다른 조직의 노선으로 변경할 수 없습니다.");
            }

            bus.setRouteId(new DBRef("routes", route.getId()));

            // 라우트 변경 시 정류장 인덱스 초기화
            bus.setPrevStationIdx(0);
            bus.setPrevStationId(null);
            bus.setLastStationTime(null);
        }

        // 좌석 정보 업데이트
        bus.setTotalSeats(busInfoUpdateDTO.getTotalSeats());
        int occupiedSeats = bus.getOccupiedSeats();

        if (occupiedSeats > busInfoUpdateDTO.getTotalSeats()) {
            log.warn("전체 좌석 수({})가 현재 사용 중인 좌석 수({})보다 적으므로 자동 조정됩니다.",
                    busInfoUpdateDTO.getTotalSeats(), occupiedSeats);
            occupiedSeats = busInfoUpdateDTO.getTotalSeats();
            bus.setOccupiedSeats(occupiedSeats);
        }

        bus.setAvailableSeats(busInfoUpdateDTO.getTotalSeats() - occupiedSeats);

        busRepository.save(bus);

        // 변경사항을 클라이언트에게 브로드캐스트
        broadcastBusStatusUpdate(bus);

        log.info("버스가 수정되었습니다: 번호={}, 실제번호={}, 조직={}, 운행여부={}",
                bus.getBusNumber(), bus.getBusRealNumber(), organizationId, bus.isOperate());
        return true;
    }

    /**
     * 버스 ID로 특정 버스 조회
     */
    public Bus getBusById(String id) {
        return busRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("버스를 찾을 수 없습니다: " + id));
    }

    /**
     * 버스 번호와 조직으로 특정 버스 조회
     */
    public Bus getBusByNumberAndOrganization(String busNumber, String organizationId) {
        return busRepository.findByBusNumberAndOrganizationId(busNumber, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        String.format("버스를 찾을 수 없습니다: 번호=%s, 조직=%s", busNumber, organizationId)));
    }

    /**
     * 실제 버스 번호와 조직으로 특정 버스 조회
     */
    public Bus getBusByRealNumberAndOrganization(String busRealNumber, String organizationId) {
        return busRepository.findByBusRealNumberAndOrganizationId(busRealNumber, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        String.format("실제 버스 번호로 버스를 찾을 수 없습니다: 실제번호=%s, 조직=%s", busRealNumber, organizationId)));
    }

    /**
     * 조직 ID로 모든 버스 조회
     */
    public List<Bus> getAllBusesByOrganizationId(String organizationId) {
        return busRepository.findByOrganizationId(organizationId);
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
     * 운행 상태별 버스 조회
     */
    public List<BusRealTimeStatusDTO> getBusesByOperationStatus(String organizationId, boolean isOperate) {
        List<Bus> buses = busRepository.findByOrganizationIdAndIsOperate(organizationId, isOperate);
        return buses.stream()
                .map(this::convertToStatusDTO)
                .collect(Collectors.toList());
    }

    /**
     * 실제 버스 번호 중복 확인
     */
    public boolean isRealNumberDuplicate(String busRealNumber, String organizationId) {
        if (busRealNumber == null || busRealNumber.trim().isEmpty()) {
            return false;
        }
        return busRepository.existsByBusRealNumberAndOrganizationId(busRealNumber.trim(), organizationId);
    }

    /**
     * 버스의 모든 정류장 상세 정보를 한 번에 조회합니다.
     * 각 정류장의 상태(지나친 정류장, 현재 정류장)와 도착 예정 시간을 포함합니다.
     *
     * @param busNumber      버스 번호
     * @param organizationId 조직 ID
     * @return 상세 정보가 포함된 정류장 목록
     */
    public List<Station> getBusStationsDetail(String busNumber, String organizationId) {
        log.info("버스 정류장 상세 정보 조회 - 버스 번호: {}, 조직: {}", busNumber, organizationId);

        // 버스 조회
        Bus bus = getBusByNumberAndOrganization(busNumber, organizationId);

        // 버스의 라우트 ID 확인
        if (bus.getRouteId() == null) {
            throw new BusinessException("버스에 할당된 노선이 없습니다.");
        }

        String routeId = bus.getRouteId().getId().toString();

        // 노선 조회
        Route route = routeRepository.findById(routeId)
                .orElseThrow(() -> new ResourceNotFoundException("해당 ID의 노선을 찾을 수 없습니다: " + routeId));

        // 조직 ID 확인
        if (!route.getOrganizationId().equals(organizationId)) {
            throw new BusinessException("다른 조직의 라우트 정보에 접근할 수 없습니다.");
        }

        // 모든 정류장 ID 추출
        List<String> stationIds = route.getStations().stream()
                .map(routeStation -> routeStation.getStationId().getId().toString())
                .collect(Collectors.toList());

        // 한 번에 모든 정류장 조회
        Map<String, Station> stationMap = stationRepository.findAllByIdIn(stationIds).stream()
                .collect(Collectors.toMap(Station::getId, station -> station));

        // 결과 목록 및 현재 정류장 ID 준비
        List<Station> resultStations = new ArrayList<>();
        String currentStationId = null;

        // 순서대로 정류장 처리
        for (int i = 0; i < route.getStations().size(); i++) {
            Route.RouteStation routeStation = route.getStations().get(i);
            String stationId = routeStation.getStationId().getId().toString();

            Station station = stationMap.get(stationId);
            if (station == null) {
                log.warn("정류장 ID {} 정보를 찾을 수 없습니다", stationId);
                continue;
            }

            // 정류장 순서와 상태 설정
            station.setSequence(i);
            station.setPassed(i <= bus.getPrevStationIdx());
            station.setCurrentStation(i == bus.getPrevStationIdx() + 1);

            // 현재 정류장인 경우 ID 저장
            if (station.isCurrentStation()) {
                currentStationId = stationId;
            }

            resultStations.add(station);
        }

        // 현재 정류장이 있으면 도착 예정 시간 추가
        if (currentStationId != null) {
            try {
                BusArrivalEstimateResponseDTO arrivalTime =
                        kakaoApiService.getMultiWaysTimeEstimate(bus.getBusNumber(), currentStationId);

                // 현재 정류장 찾아서 도착 시간 설정
                resultStations.stream()
                        .filter(Station::isCurrentStation)
                        .findFirst()
                        .ifPresent(station -> station.setEstimatedArrivalTime(arrivalTime.getEstimatedTime()));
            } catch (Exception e) {
                log.warn("도착 시간 예측 실패: {}", e.getMessage());
            }
        }

        log.info("최종 정류장 결과 {}", resultStations);
        return resultStations;
    }

    /**
     * 조직별 모든 버스 상태 조회
     */
    public List<BusRealTimeStatusDTO> getAllBusStatusByOrganizationId(String organizationId) {
        List<Bus> buses = getAllBusesByOrganizationId(organizationId);
        return buses.stream()
                .map(this::convertToStatusDTO)
                .collect(Collectors.toList());
    }

    /**
     * 특정 정류장을 경유하는 조직의 모든 버스 조회
     */
    public List<BusRealTimeStatusDTO> getBusesByStationAndOrganization(String stationId, String organizationId) {
        log.info("특정 정류장을 경유하는 버스 조회 - 정류장 ID: {}, 조직 ID: {}", stationId, organizationId);

        // 조직의 모든 버스 조회
        List<Bus> organizationBuses = getAllBusesByOrganizationId(organizationId);
        List<BusRealTimeStatusDTO> result = new ArrayList<>();

        // 각 버스에 대해 라우트를 검사하여 해당 정류장을 경유하는지 확인
        for (Bus bus : organizationBuses) {
            if (bus.getRouteId() == null) continue;

            String routeId = bus.getRouteId().getId().toString();
            Route route = routeRepository.findById(routeId).orElse(null);

            if (route != null && route.getStations() != null) {
                // 라우트의 모든 정류장을 확인
                boolean containsStation = route.getStations().stream()
                        .anyMatch(routeStation -> {
                            String stationRefId = routeStation.getStationId().getId().toString();
                            return stationRefId.equals(stationId);
                        });

                // 해당 정류장을 경유하는 경우 결과에 추가
                if (containsStation) {
                    result.add(convertToStatusDTO(bus));
                }
            }
        }

        log.info("정류장 {} 경유 버스 {} 대 조회됨", stationId, result.size());
        return result;
    }

    /**
     * 버스 객체를 StatusDTO로 변환
     */
    private BusRealTimeStatusDTO convertToStatusDTO(Bus bus) {
        // 라우트 정보 조회
        Route route = null;
        if (bus.getRouteId() != null) {
            try {
                route = routeRepository.findById(bus.getRouteId().getId().toString()).orElse(null);
            } catch (Exception e) {
                log.error("라우트 정보 조회 중 오류 발생: {}", bus.getRouteId().getId(), e);
            }
        }

        String routeName = (route != null) ? route.getRouteName() : "알 수 없음";
        int totalStations = (route != null && route.getStations() != null) ? route.getStations().size() : 0;

        // 현재/마지막 정류장 정보 조회
        String currentStationName = "알 수 없음";
        if (bus.getPrevStationId() != null) {
            try {
                Station station = stationRepository.findById(bus.getPrevStationId()).orElse(null);
                if (station != null) {
                    currentStationName = station.getName();
                }
            } catch (Exception e) {
                log.error("정류장 정보 조회 중 오류 발생: {}", bus.getPrevStationId(), e);
            }
        }

        // 상태 DTO 생성
        BusRealTimeStatusDTO statusDTO = new BusRealTimeStatusDTO();
        statusDTO.setBusId(bus.getId());
        statusDTO.setBusNumber(bus.getBusNumber());
        statusDTO.setBusRealNumber(bus.getBusRealNumber());
        statusDTO.setRouteName(routeName);
        statusDTO.setOrganizationId(bus.getOrganizationId());
        statusDTO.setLatitude(bus.getLocation() != null ? bus.getLocation().getY() : 0);
        statusDTO.setLongitude(bus.getLocation() != null ? bus.getLocation().getX() : 0);
        statusDTO.setTotalSeats(bus.getTotalSeats());
        statusDTO.setOccupiedSeats(bus.getOccupiedSeats());
        statusDTO.setAvailableSeats(bus.getAvailableSeats());
        statusDTO.setCurrentStationName(currentStationName);
        statusDTO.setLastUpdateTime(bus.getTimestamp() != null ? bus.getTimestamp().toEpochMilli() : System.currentTimeMillis());
        statusDTO.setCurrentStationIndex(bus.getPrevStationIdx());
        statusDTO.setTotalStations(totalStations);
        statusDTO.setOperate(bus.isOperate());

        return statusDTO;
    }

    /**
     * 버스 상태 업데이트를 클라이언트에게 브로드캐스트
     */
    public void broadcastBusStatusUpdate(Bus bus) {
        BusRealTimeStatusDTO statusDTO = convertToStatusDTO(bus);
        eventPublisher.publishEvent(new BusStatusUpdateEvent(bus.getOrganizationId(), statusDTO));
    }

    /**
     * 버스 위치 정보 얻기
     */
    public LocationDTO getBusLocationByBusNumber(String busNumber, String organizationId) {
        Bus bus = getBusByNumberAndOrganization(busNumber, organizationId);

        LocationDTO locationDTO = new LocationDTO();
        if (bus.getLocation() != null) {
            locationDTO.setLatitude(bus.getLocation().getY());
            locationDTO.setLongitude(bus.getLocation().getX());
        } else {
            locationDTO.setLatitude(0);
            locationDTO.setLongitude(0);
        }
        locationDTO.setTimestamp(bus.getTimestamp());

        return locationDTO;
    }

    /**
     * 버스 좌석 정보 얻기
     */
    public BusSeatDTO getBusSeatsByBusNumber(String busNumber, String organizationId) {
        Bus bus = getBusByNumberAndOrganization(busNumber, organizationId);

        BusSeatDTO busSeatDTO = new BusSeatDTO();
        busSeatDTO.setBusNumber(bus.getBusNumber());
        busSeatDTO.setBusRealNumber(bus.getBusRealNumber()); // 새 필드
        busSeatDTO.setAvailableSeats(bus.getAvailableSeats());
        busSeatDTO.setOccupiedSeats(bus.getOccupiedSeats());
        busSeatDTO.setTotalSeats(bus.getTotalSeats());
        busSeatDTO.setOperate(bus.isOperate()); // 새 필드

        return busSeatDTO;
    }

    /**
     * 정기적으로 버스 위치 업데이트 적용 (3초마다로 변경)
     * WebSocket으로 받은 위치 정보를 DB에 반영하는 핵심 메서드
     */
    @Scheduled(fixedRate = 3000) // 10초에서 3초로 단축
    public void flushLocationUpdates() {
        List<BusRealTimeLocationDTO> updates;

        // 1. 대기 중인 업데이트 가져오기
        synchronized (pendingLocationUpdates) {
            if (pendingLocationUpdates.isEmpty()) {
                return;
            }

            updates = new ArrayList<>(pendingLocationUpdates.values());
            pendingLocationUpdates.clear();
        }

        log.info("🔄 [BusService] 위치 업데이트 처리 시작 - {} 건", updates.size());

        int successCount = 0;
        int failCount = 0;
        int skipCount = 0;
        long startTime = System.currentTimeMillis();

        // 2. 각 버스의 위치 업데이트 처리
        for (BusRealTimeLocationDTO update : updates) {
            try {
                // 위치 유효성 검증
                if (update.getLocation().getX() == 0.0 && update.getLocation().getY() == 0.0) {
                    log.warn("🚫 [BusService] (0, 0) 위치 업데이트 건너뛰기: 버스 번호 = {}",
                            update.getBusNumber());
                    skipCount++;
                    continue;
                }

                // GPS 좌표 범위 검증
                if (update.getLocation().getX() < -90 || update.getLocation().getX() > 90 ||
                        update.getLocation().getY() < -180 || update.getLocation().getY() > 180) {
                    log.warn("🚫 [BusService] 잘못된 GPS 좌표 건너뛰기: 버스 = {}, 위치 = ({}, {})",
                            update.getBusNumber(), update.getLocation().getY(), update.getLocation().getX());
                    skipCount++;
                    continue;
                }

                // 버스 조회
                Query query = new Query(Criteria.where("busNumber").is(update.getBusNumber())
                        .and("organizationId").is(update.getOrganizationId()));

                Bus existingBus = mongoOperations.findOne(query, Bus.class);

                if (existingBus == null) {
                    log.warn("🚌 [BusService] 버스를 찾을 수 없음: {}, 조직: {}",
                            update.getBusNumber(), update.getOrganizationId());
                    failCount++;
                    continue;
                }

                // 운행 중지된 버스인 경우 위치 업데이트 건너뛰기
                if (!existingBus.isOperate()) {
                    log.debug("🛑 [BusService] 운행 중지된 버스 위치 업데이트 건너뛰기: {}",
                            update.getBusNumber());
                    skipCount++;
                    continue;
                }

                // 이전 위치와 동일한지 확인 (선택적)
                GeoJsonPoint currentLocation = existingBus.getLocation();
                if (currentLocation != null &&
                        Math.abs(currentLocation.getX() - update.getLocation().getX()) < 0.000001 &&
                        Math.abs(currentLocation.getY() - update.getLocation().getY()) < 0.000001) {
                    log.debug("📍 [BusService] 위치 변화 없음 - 업데이트 건너뛰기: 버스 = {}",
                            update.getBusNumber());
                    // 좌석 정보만 변경되었을 수 있으므로 계속 처리
                }

                // 위치 및 좌석 정보 업데이트
                GeoJsonPoint newLocation = new GeoJsonPoint(update.getLocation().getY(), update.getLocation().getX());
                Instant timestamp = update.getTimestamp();

                log.info("🚌 [BusService] 버스 {} 위치 업데이트 시작 - 위치: ({}, {}), 승객: {}명",
                        update.getBusNumber(), update.getLocation().getY(), update.getLocation().getX(),
                        update.getOccupiedSeats());

                // 현재 위치와 가장 가까운 정류장 찾기
                Route.RouteStation nearestStation = findNearestStation(existingBus, newLocation);

                Update mongoUpdate = new Update()
                        .set("location", newLocation)
                        .set("timestamp", timestamp)
                        .set("occupiedSeats", update.getOccupiedSeats())
                        .set("availableSeats", existingBus.getTotalSeats() - update.getOccupiedSeats());

                // 가까운 정류장이 있고, 이전 정류장과 다른 경우에만 업데이트
                if (nearestStation != null &&
                        (existingBus.getPrevStationId() == null ||
                                !existingBus.getPrevStationId().equals(nearestStation.getStationId().getId().toString()))) {

                    mongoUpdate.set("prevStationId", nearestStation.getStationId().getId().toString())
                            .set("lastStationTime", timestamp)
                            .set("prevStationIdx", nearestStation.getSequence());

                    log.info("🚏 [BusService] 버스 {} 정류장 업데이트: 시퀀스={}, 정류장ID={}",
                            update.getBusNumber(), nearestStation.getSequence(),
                            nearestStation.getStationId().getId());
                }

                // MongoDB 업데이트 실행
                mongoOperations.updateFirst(query, mongoUpdate, Bus.class);
                successCount++;

                log.info("✅ [BusService] 버스 {} 업데이트 완료 - 새 위치: Point [x={}, y={}], 승객: {}명",
                        update.getBusNumber(), newLocation.getX(), newLocation.getY(),
                        update.getOccupiedSeats());

                // 3. 업데이트된 버스 정보 조회 및 이벤트 발생
                Bus updatedBus = mongoOperations.findOne(query, Bus.class);
                if (updatedBus != null) {
                    // 클라이언트에게 상태 업데이트 브로드캐스트
                    broadcastBusStatusUpdate(updatedBus);

                    // 정류장 도착/출발 이벤트 처리
                    if (nearestStation != null && existingBus.getPrevStationIdx() != nearestStation.getSequence()) {
                        publishStationEvent(updatedBus, nearestStation);
                    }
                }

            } catch (Exception e) {
                log.error("❌ [BusService] 버스 {} 위치 업데이트 중 오류 발생",
                        update.getBusNumber(), e);
                failCount++;
            }
        }

        long elapsedTime = System.currentTimeMillis() - startTime;

        log.info("✅ [BusService] 위치 업데이트 처리 완료 - 성공: {} 건, 실패: {} 건, 건너뛴: {} 건, 소요 시간: {} ms",
                successCount, failCount, skipCount, elapsedTime);

        // 4. 성능 모니터링
        if (elapsedTime > 2000) { // 2초 이상 걸린 경우 경고
            log.warn("⚠️ [BusService] 위치 업데이트 처리 시간이 길어졌습니다: {} ms", elapsedTime);
        }
    }

    /**
     * 정류장 이벤트 발행
     */
    private void publishStationEvent(Bus bus, Route.RouteStation station) {
        try {
            String stationId = station.getStationId().getId().toString();
            Station stationInfo = stationRepository.findById(stationId).orElse(null);

            if (stationInfo != null) {
                Map<String, Object> eventData = Map.of(
                        "busNumber", bus.getBusNumber(),
                        "busRealNumber", bus.getBusRealNumber() != null ? bus.getBusRealNumber() : "",
                        "stationName", stationInfo.getName(),
                        "stationSequence", station.getSequence(),
                        "timestamp", bus.getTimestamp().toEpochMilli(),
                        "occupiedSeats", bus.getOccupiedSeats(),
                        "availableSeats", bus.getAvailableSeats()
                );

                // 정류장 도착 이벤트 발행
                eventPublisher.publishEvent(new StationArrivalEvent(
                        bus.getOrganizationId(),
                        bus.getBusNumber(),
                        stationInfo.getName(),
                        eventData
                ));

                log.info("정류장 도착 이벤트 발행 - 버스: {}, 정류장: {} ({}번째)",
                        bus.getBusNumber(), stationInfo.getName(), station.getSequence());
            }
        } catch (Exception e) {
            log.error("정류장 이벤트 발행 중 오류: {}", e.getMessage());
        }
    }

    /**
     * 정류장 도착 이벤트 클래스
     */
    public record StationArrivalEvent(
            String organizationId,
            String busNumber,
            String stationName,
            Map<String, Object> eventData
    ) {
    }

    /**
     * 현재 위치에서 가장 가까운 정류장 찾기 (개선된 버전)
     */
    private Route.RouteStation findNearestStation(Bus bus, GeoJsonPoint location) {
        if (bus.getRouteId() == null) {
            return null;
        }

        // 라우트 정보 조회
        Route route = routeRepository.findById(bus.getRouteId().getId().toString()).orElse(null);
        if (route == null || route.getStations() == null || route.getStations().isEmpty()) {
            return null;
        }

        Route.RouteStation nearestStation = null;
        double minDistance = STATION_RADIUS;

        // 현재 인덱스 기준 주변 정류장 탐색 (전체 노선 탐색보다 효율적)
        int currentIdx = bus.getPrevStationIdx();
        int startIdx = Math.max(0, currentIdx - 1);
        int endIdx = Math.min(route.getStations().size(), currentIdx + 3);

        for (int i = startIdx; i < endIdx; i++) {
            if (i >= route.getStations().size()) break;

            Route.RouteStation routeStation = route.getStations().get(i);
            try {
                String stationId = routeStation.getStationId().getId().toString();
                Station station = stationRepository.findById(stationId).orElse(null);

                if (station != null && station.getLocation() != null) {
                    double distance = calculateDistance(
                            location.getY(), location.getX(),
                            station.getLocation().getY(), station.getLocation().getX()
                    );

                    // 이전 정류장보다 뒤에 있는 정류장만 고려 (역주행 방지)
                    if (distance < minDistance && i >= currentIdx) {
                        minDistance = distance;
                        nearestStation = routeStation;
                    }
                }
            } catch (Exception e) {
                log.error("정류장 정보 조회 중 오류 발생: {}", routeStation.getStationId(), e);
            }
        }

        // 근처에 정류장이 없고 현재 위치가 마지막 정류장을 지났다면
        if (nearestStation == null && currentIdx == route.getStations().size() - 1) {
            log.debug("버스 {}가 종점에 도착했거나 지나쳤습니다.", bus.getBusNumber());
        }

        return nearestStation;
    }

    /**
     * 대기 중인 위치 업데이트 수 조회
     */
    public int getPendingLocationUpdatesCount() {
        return pendingLocationUpdates.size();
    }


    /**
     * 버스 비활성 상태 업데이트
     */
    public void updateBusInactiveStatus(String busNumber) {
        try {
            // 현재는 로그만 남김 - 필요시 DB 업데이트 로직 추가
            log.info("버스 {} 비활성 상태로 업데이트", busNumber);

            // 향후 확장: DB에서 버스 상태를 'INACTIVE'로 업데이트
            // Bus bus = getBusByNumberAndOrganization(busNumber, organizationId);
            // bus.setActive(false);
            // busRepository.save(bus);

        } catch (Exception e) {
            log.error("버스 비활성 상태 업데이트 실패: {}", e.getMessage());
        }
    }


    /**
     * 두 위치 사이의 거리 계산 (Haversine 공식)
     */
    public double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        final double R = 6371000; // 지구의 반지름 (미터)

        // 위도, 경도를 라디안으로 변환
        double lat1Rad = Math.toRadians(lat1);
        double lon1Rad = Math.toRadians(lon1);
        double lat2Rad = Math.toRadians(lat2);
        double lon2Rad = Math.toRadians(lon2);

        // 위도, 경도 차이
        double dLat = lat2Rad - lat1Rad;
        double dLon = lon2Rad - lon1Rad;

        // Haversine 공식
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                Math.cos(lat1Rad) * Math.cos(lat2Rad) *
                        Math.sin(dLon / 2) * Math.sin(dLon / 2);

        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

        // 최종 거리 (미터 단위)
        return R * c;
    }
}