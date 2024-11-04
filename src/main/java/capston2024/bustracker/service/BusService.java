package capston2024.bustracker.service;

import capston2024.bustracker.config.dto.*;
import capston2024.bustracker.domain.Bus;
import capston2024.bustracker.exception.ResourceNotFoundException;
import capston2024.bustracker.repository.BusRepository;
import com.mongodb.DBRef;
import com.mongodb.client.result.UpdateResult;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.aggregation.ConditionalOperators;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
@Slf4j
@AllArgsConstructor
public class BusService {

    private final BusRepository busRepository;
    private final StationService stationService;
    private final MongoOperations mongoOperations;
    private final Map<String, BusUpdateDTO> pendingUpdates = new ConcurrentHashMap<>();

    public boolean createBus(BusRegisterDTO busRegisterDTO) {
        List<String> stationNames = busRegisterDTO.getStationNames();

        if (stationService.isValidStationNames(stationNames)) {
            /* Stream 생성 - map - .collect(Collectors.toList())
             List형을 개별 연산을 가능케하도록 Stream 구성,
             map을 통해 개별적 연산 수행
             수행된 연산을 .collect(Collectors.toList()) 통해 List로 다시 모음
            */
            List<Bus.StationInfo> stationInfoList = !stationNames.isEmpty()
                    ? stationNames.stream()
                    .map(name -> {
                        String stationId = stationService.findStationIdByName(name);
                        return new Bus.StationInfo(new DBRef("station", stationId), name);
                    })
                    .collect(Collectors.toList())
                    : new ArrayList<>();

            Bus bus = Bus.builder()
                    .busNumber(busRegisterDTO.getBusNumber())
                    .stations(stationInfoList)
                    .totalSeats(busRegisterDTO.getTotalSeats())
                    .occupiedSeats(0)
                    .availableSeats(busRegisterDTO.getTotalSeats())
                    .location(new GeoJsonPoint(35.495299450684456, 129.4172414821444))
                    .timestamp(Instant.now())
                    .build();

            busRepository.save(bus);
            return true;
        }
        return false;
    }

    // 2. 버스 삭제
    public boolean removeBus(String busNumber) {
        busRepository.delete(busRepository.findBusByBusNumber(busNumber).orElseThrow(()-> new ResourceNotFoundException("버스를 찾을 수 없습니다.")));
        return true;
    }

    // 3. 버스 수정 - 전체 버스 수정 사항
    public boolean modifyBus(BusDTO busDTO) {
        log.info("버스 수정 요청 받음: {}", busDTO);  // 입력값 확인용

        // 입력값 검증
        if (busDTO.getBusNumber() == null || busDTO.getBusNumber().trim().isEmpty()) {
            log.error("버스 번호가 유효하지 않습니다");
            throw new IllegalArgumentException("버스 번호가 유효하지 않습니다.");
        }
        if (busDTO.getTotalSeats() < 0) {
            log.error("좌석 수가 유효하지 않습니다: {}", busDTO.getTotalSeats());
            throw new IllegalArgumentException("전체 좌석 수는 0보다 작을 수 없습니다.");
        }

        List<String> stationNames = busDTO.getStationNames();
        log.info("검증할 정류장 목록: {}", stationNames);  // 정류장 목록 확인용

        // 버스 id로 버스 찾기
        Bus bus = busRepository.findById(busDTO.getId())
                .orElseThrow(() -> new ResourceNotFoundException("해당 id의 버스를 찾을 수 없습니다: " + busDTO.getId()));
        log.info("기존 버스 정보: {}", bus);  // 기존 버스 정보 확인용

        if (!stationService.isValidStationNames(stationNames)) {
            log.error("유효하지 않은 정류장 이름이 포함되어 있습니다: {}", stationNames);
            return false;
        }
        /* Stream 생성 - map - .collect(Collectors.toList())
         List형을 개별 연산을 가능케하도록 Stream 구성,
         map을 통해 개별적 연산 수행
         수행된 연산을 .collect(Collectors.toList()) 통해 List로 다시 모음
        */
        List<Bus.StationInfo> stationInfoList = !stationNames.isEmpty()
                ? stationNames.stream()
                .map(name -> {
                    String stationId = stationService.findStationIdByName(name);
                    return new Bus.StationInfo(new DBRef("stations", stationId), name);
                })
                .collect(Collectors.toList())
                : new ArrayList<>();

        log.info("stationInfoList : {}", stationInfoList);
        bus.setStations(stationInfoList);
        bus.setBusNumber(busDTO.getBusNumber());
        bus.setTotalSeats(busDTO.getTotalSeats());

        // 사용 가능한 좌석 수 업데이트
        int occupiedSeats = bus.getOccupiedSeats();
        if (occupiedSeats > busDTO.getTotalSeats()) {
            log.warn("전체 좌석 수({})가 현재 사용 중인 좌석 수({})보다 적으므로 사용 좌석수와 전체 좌석 수가 일치 하도록 자동 조정됩니다.", busDTO.getTotalSeats(), occupiedSeats);
            occupiedSeats = busDTO.getTotalSeats();
        }
        bus.setAvailableSeats(busDTO.getTotalSeats() - occupiedSeats);

        log.info("버스가 성공적으로 수정됨 {}", bus);
        busRepository.save(bus);  // 여기서는 UPDATE 동작
        return true;
    }

    // 4. 모든 버스 조회
    public List<Bus> getAllBuses() {
        return busRepository.findAll();
    }

    // 특정 버스 조회
    public Bus getBusByNumber(String busNumber) {
        return busRepository.findBusByBusNumber(busNumber).orElseThrow(()->new ResourceNotFoundException("버스를 찾을 수 없습니다."));
    }

    public List<Bus> getBusesByStationId(String stationId) {
        log.info("해당 정류장이 포함된 버스를 찾는 중.. stationId: {}", stationId);

        Query query = new Query(Criteria.where("stations.stationRef.$id").is(stationId));
        log.info("생성된 쿼리: {}", query);

        List<Bus> buses = mongoOperations.find(query, Bus.class);
        log.info("찾은 버스 수: {}", buses.size());

        return buses;
    }

    public List<String> getAllStationNames(String busNumber) {
        Bus bus = getBusByNumber(busNumber);

        return bus.getStations().stream()
                .map(Bus.StationInfo::getStationName)
                .collect(Collectors.toList());
    }

    /**
     * 웹 소켓에서 받아오는 서비스 - 버스 위치 정보, 버스 좌석 정보
     * @param csvData ( busNumber, location(lat, lst) )
     * @return CompletableFuture.xFuture(e)
     */
    @Async
    public CompletableFuture<Void> processBusLocationAsync(String csvData) {
        return CompletableFuture.runAsync(() -> {
            try {
                BusUpdateDTO update = parseCsvToBusUpdate(csvData);
                log.info("새로운 업데이트 수신: {}", update);
                pendingUpdates.compute(update.getBusNumber(), (key, existing) -> {
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


    private BusUpdateDTO parseCsvToBusUpdate(String csvData) {
        String[] parts = csvData.split(",");
        if (parts.length != 4) {
            throw new IllegalArgumentException("CSV 형식이 알맞지 않습니다. 형식: 버스번호,위도,경도,좌석수");
        }

        String busNumber = parts[0];
        double latitude = Double.parseDouble(parts[1]);
        double longitude = Double.parseDouble(parts[2]);
        int seats = Integer.parseInt(parts[3]);
        Instant timestamp = Instant.now();

        return new BusUpdateDTO(busNumber, new GeoJsonPoint(longitude, latitude), timestamp, seats);
    }

    @Scheduled(fixedRate = 5000)
    public void flushLocationUpdates() {
        List<BusUpdateDTO> updates;
        synchronized (pendingUpdates) {
            updates = new ArrayList<>(pendingUpdates.values());
            pendingUpdates.clear();
        }

        for (BusUpdateDTO update : updates) {
            try {
                Query query = new Query(Criteria.where("busNumber").is(update.getBusNumber()));
                Bus existingBus = mongoOperations.findOne(query, Bus.class);
                int totalSeats = (existingBus != null)
                        ? existingBus.getTotalSeats()
                        : 40;  // 기본값
                Update mongoUpdate = new Update()
                        .set("location", update.getLocation())
                        .set("timestamp", update.getTimestamp())
                        .set("occupiedSeats", update.getSeats())
                        .set("availableSeats", totalSeats-update.getSeats());

                log.info("업데이트 쿼리: {}", mongoUpdate);

                UpdateResult result = mongoOperations.updateFirst(query, mongoUpdate, "Bus");
                log.info("버스 {} 업데이트 결과: 일치 문서 {}, 수정된 문서 {}",
                        update.getBusNumber(), result.getMatchedCount(), result.getModifiedCount());

                // 업데이트 후 문서 확인
                Bus updatedBus = mongoOperations.findOne(query, Bus.class, "Bus");
                log.info("업데이트된 버스 정보: {}", updatedBus);

            } catch (Exception e) {
                log.error("버스 {} 업데이트 중 오류 발생: ", update.getBusNumber(), e);
            }
        }

        log.info("{} 개의 버스 위치와 좌석 정보가 업데이트되었습니다.", updates.size());
    }


    public BusSeatDTO getBusSeatsByBusNumber(String busNumber) {
        Bus bus = getBusByNumber(busNumber);
        BusSeatDTO busSeatDTO = new BusSeatDTO();
        busSeatDTO.setAvailableSeats(bus.getAvailableSeats());
        busSeatDTO.setOccupiedSeats(bus.getOccupiedSeats());
        busSeatDTO.setTotalSeats(bus.getTotalSeats());
        return busSeatDTO;
    }

    public LocationDTO getBusLocationByBusNumber(String busNumber) {
        Bus bus = getBusByNumber(busNumber);
        LocationDTO locationDTO = new LocationDTO();
        locationDTO.setLatitude(bus.getLocation().getX());
        locationDTO.setLongitude(bus.getLocation().getY());
        locationDTO.setTimestamp(Instant.now());
        return locationDTO;
    }
}


/* 이전 코드
//    @Async
//    public CompletableFuture<Bus> processBusLocationAsync(String csvData) {
//        return CompletableFuture.supplyAsync(() -> {
//            try {
//                return parseCsvToBus(csvData);
//            } catch (Exception e) {
//                log.error("버스 위치 업데이트 중 오류 발생: {}", e.getMessage());
//                throw new CompletionException(e);
//            }
//        });
//    }
//
//    //파싱된 버스 위치정보는 무조건 modify 여야한다.
//    @Transactional
//    protected Bus parseCsvToBus(String csvData) {
//        String[] parts = csvData.split(",");
//        log.info("받은 csvData : {}", csvData);
//        if (parts.length < 2) {
//            throw new IllegalArgumentException("CSV 형식이 알맞지 않습니다.");
//        }
//        Bus bus = getBusByNumber(parts[0]);
//        log.info("버스 객체 : {}", bus);
//        bus.setLocation(new GeoJsonPoint(Double.parseDouble(parts[1]), Double.parseDouble(parts[2])));
//        bus.setTimestamp(Instant.now());
//        return bus;
//    }
//

 */


