package capston2024.bustracker.service;

import capston2024.bustracker.config.dto.BusRealTimeLocationDTO;
import capston2024.bustracker.config.dto.BusRealTimeStatusDTO;
import capston2024.bustracker.domain.Bus;
import capston2024.bustracker.domain.Route;
import capston2024.bustracker.domain.Station;
import capston2024.bustracker.repository.BusRepository;
import capston2024.bustracker.repository.RouteRepository;
import capston2024.bustracker.repository.StationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
@RequiredArgsConstructor
public class BusLocationService {

    private static final double STATION_RADIUS = 120.0; // 120미터

    private final BusRepository busRepository;
    private final RouteRepository routeRepository;
    private final StationRepository stationRepository;
    private final MongoOperations mongoOperations;
    private final ApplicationEventPublisher eventPublisher;

    private final Map<String, BusRealTimeLocationDTO> pendingLocationUpdates = new ConcurrentHashMap<>();

    /**
     * 비동기적으로 버스 위치를 처리합니다.
     * @param csvData 아두이노에서 받은 CSV 데이터
     * @return CompletionStage
     */
    public CompletionStage<Void> processBusLocationAsync(String csvData) {
        return CompletableFuture.runAsync(() -> {
            try {
                BusRealTimeLocationDTO update = parseCsvToBusUpdate(csvData);
                pendingLocationUpdates.compute(update.getBusNumber(), (key, existing) -> {
                    if (existing == null || update.getTimestamp().isAfter(existing.getTimestamp())) {
                        return update;
                    }
                    return existing;
                });
            } catch (Exception e) {
                log.error("버스 위치 CSV 처리 중 오류 발생: ", e);
            }
        });
    }

    /**
     * 정기적으로 대기 중인 위치 업데이트를 DB에 반영합니다.
     */
    @Scheduled(fixedRate = 3000)
    public void flushLocationUpdates() {
        if (pendingLocationUpdates.isEmpty()) {
            return;
        }

        List<BusRealTimeLocationDTO> updates = new ArrayList<>(pendingLocationUpdates.values());
        pendingLocationUpdates.clear();

        log.info("🔄 위치 업데이트 처리 시작 - {} 건", updates.size());

        for (BusRealTimeLocationDTO update : updates) {
            try {
                updateBusLocation(update);
            } catch (Exception e) {
                log.error("❌ 버스 {} 위치 업데이트 중 오류 발생", update.getBusNumber(), e);
            }
        }
    }

    /**
     * 단일 버스 위치 정보를 업데이트합니다.
     * @param update 업데이트할 위치 정보 DTO
     */
    private void updateBusLocation(BusRealTimeLocationDTO update) {
        Query query = new Query(Criteria.where("busNumber").is(update.getBusNumber())
                .and("organizationId").is(update.getOrganizationId()));
        Bus existingBus = mongoOperations.findOne(query, Bus.class);

        if (existingBus == null || !existingBus.isOperate()) {
            return; // 버스가 없거나 운행 중이 아니면 업데이트 안 함
        }

        // 좌석 수 유효성 검증
        int occupiedSeats = update.getOccupiedSeats();
        if (occupiedSeats > existingBus.getTotalSeats()){
            log.warn("수신된 탑승 좌석 수({})가 전체 좌석 수({})를 초과하여 조정됩니다.", occupiedSeats, existingBus.getTotalSeats());
            occupiedSeats = existingBus.getTotalSeats();
        }

        GeoJsonPoint newLocation = new GeoJsonPoint(update.getLocation().getY(), update.getLocation().getX());
        Route.RouteStation nearestStation = findNearestStation(existingBus, newLocation);

        Update mongoUpdate = new Update()
                .set("location", newLocation)
                .set("timestamp", update.getTimestamp())
                .set("occupiedSeats", occupiedSeats)
                .set("availableSeats", existingBus.getTotalSeats() - occupiedSeats);

        if (nearestStation != null && !nearestStation.getStationId().getId().toString().equals(existingBus.getPrevStationId())) {
            mongoUpdate.set("prevStationId", nearestStation.getStationId().getId().toString())
                    .set("lastStationTime", update.getTimestamp())
                    .set("prevStationIdx", nearestStation.getSequence());
        }

        mongoOperations.updateFirst(query, mongoUpdate, Bus.class);

        Bus updatedBus = mongoOperations.findOne(query, Bus.class);
        if (updatedBus != null) {
            broadcastBusStatusUpdate(updatedBus);
        }
    }

    /**
     * 버스 상태 업데이트 이벤트를 발행합니다.
     * @param bus 업데이트된 버스 객체
     */
    private void broadcastBusStatusUpdate(Bus bus) {
        BusRealTimeStatusDTO statusDTO = convertToStatusDTO(bus);
        eventPublisher.publishEvent(new BusService.BusStatusUpdateEvent(bus.getOrganizationId(), statusDTO));
    }


    private BusRealTimeLocationDTO parseCsvToBusUpdate(String csvData) {
        String[] parts = csvData.split(",");
        if (parts.length != 5) {
            throw new IllegalArgumentException("CSV 형식이 올바르지 않습니다. 형식: 버스번호,조직코드,위도,경도,좌석수");
        }
        String busNumber = parts[0].trim();
        String organizationId = parts[1].trim();
        double latitude = Double.parseDouble(parts[2].trim());
        double longitude = Double.parseDouble(parts[3].trim());
        int occupiedSeats = Integer.parseInt(parts[4].trim());

        return new BusRealTimeLocationDTO(busNumber, organizationId, new GeoJsonPoint(latitude, longitude), occupiedSeats, Instant.now());
    }

    private Route.RouteStation findNearestStation(Bus bus, GeoJsonPoint location) {
        if (bus.getRouteId() == null) return null;

        Route route = routeRepository.findById(bus.getRouteId().getId().toString()).orElse(null);
        if (route == null || route.getStations() == null || route.getStations().isEmpty()) return null;

        Route.RouteStation nearestStation = null;
        double minDistance = STATION_RADIUS;

        int currentIdx = bus.getPrevStationIdx();
        for (int i = currentIdx; i < route.getStations().size(); i++) {
            Route.RouteStation routeStation = route.getStations().get(i);
            Station station = stationRepository.findById(routeStation.getStationId().getId().toString()).orElse(null);
            if (station != null && station.getLocation() != null) {
                double distance = calculateDistance(location.getY(), location.getX(), station.getLocation().getY(), station.getLocation().getX());
                if (distance < minDistance) {
                    minDistance = distance;
                    nearestStation = routeStation;
                }
            }
        }
        return nearestStation;
    }

    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        final double R = 6371000; // 지구 반지름 (미터)
        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);
        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
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