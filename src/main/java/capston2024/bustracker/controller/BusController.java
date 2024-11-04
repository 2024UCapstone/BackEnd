package capston2024.bustracker.controller;

import capston2024.bustracker.config.dto.*;
import capston2024.bustracker.domain.Bus;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.exception.ResourceNotFoundException;
import capston2024.bustracker.exception.UnauthorizedException;
import capston2024.bustracker.service.BusService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.checkerframework.checker.units.qual.A;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/bus")
@RequiredArgsConstructor
@Slf4j
public class BusController {

    private final BusService busService;

    // 1. 버스 추가 (POST)
    @PostMapping()
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Boolean>> createBus(@RequestBody BusRegisterDTO busRegisterDTO) {
        boolean result = busService.createBus(busRegisterDTO);
        return ResponseEntity.ok(new ApiResponse<>(result, "성공적으로 버스가 추가되었습니다."));
    }

    // 2. 버스 삭제 (DELETE)
    @DeleteMapping("/{busNumber}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Boolean>> deleteBus(@PathVariable String busNumber) {
        boolean result = busService.removeBus(busNumber);
        return ResponseEntity.ok(new ApiResponse<>(result,"성공적으로 버스가 삭제되었습니다."));
    }

    // 3. 버스 수정 (PUT)
    @PutMapping()
//    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Boolean>> updateBus(@RequestBody BusDTO busDTO) {
        boolean result = busService.modifyBus(busDTO);
        return ResponseEntity.ok(new ApiResponse<>(result, "버스가 성공적으로 수정되었습니다."));
    }

    // 4. 버스 조회 (GET)
    @GetMapping()
    public ResponseEntity<ApiResponse<List<Bus>>> getAllBuses() {
        List<Bus> buses = busService.getAllBuses();
        return ResponseEntity.ok(new ApiResponse<>(buses, "모든 버스가 성공적으로 조회되었습니다."));
    }

    @GetMapping("/stations/{stationId}")
    public ResponseEntity<ApiResponse<List<Bus>>> getBusesByStationId(@PathVariable String stationId){
        List<Bus> bus = busService.getBusesByStationId(stationId);
        return ResponseEntity.ok(new ApiResponse<>(bus, "버스 목록이 성공적으로 조회되었습니다."));
    }

    //버스의 모든 정류장 이름 출력하기
    @GetMapping("/stationNames/{busNumber}")
    public ResponseEntity<ApiResponse<List<String>>> getStationsByBusNumber(@PathVariable String busNumber) {
        List<String> stationList = busService.getAllStationNames(busNumber);
        return ResponseEntity.ok(new ApiResponse<>(stationList, "해당 버스의 정류장 목록이 성공적으로 조회되었습니다."));
    }

    // 특정 버스 조회 (GET)
    @GetMapping("/{busNumber}")
    public ResponseEntity<ApiResponse<Bus>> getBusByNumber(@PathVariable String busNumber) {
        Bus bus = busService.getBusByNumber(busNumber);
        return ResponseEntity.ok(new ApiResponse<>(bus, "버스가 성공적으로 조회되었습니다."));
    }

    // 버스 좌석 조회 (GET)
    @GetMapping("/seats/{busNumber}")
    public ResponseEntity<ApiResponse<BusSeatDTO>> getBusSeatsByBusNumber(@PathVariable String busNumber){
        BusSeatDTO seats = busService.getBusSeatsByBusNumber(busNumber);
        return ResponseEntity.ok(new ApiResponse<>(seats, "좌석이 성공적으로 반환되었습니다."));
    }

    @GetMapping("/location/{busNumber}")
    public ResponseEntity<ApiResponse<LocationDTO>> getBusLocationByBusNumber(@PathVariable String busNumber){
        LocationDTO locations = busService.getBusLocationByBusNumber(busNumber);
        return ResponseEntity.ok(new ApiResponse<>(locations, "좌표 정보가 성공적으로 반환되었습니다."));
    }

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadRequestException(UnauthorizedException ex) {
        log.error("비지니스 서비스 로직 예외: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse<>(null, ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Void>> handleIllegalArgumentException(IllegalArgumentException ex) {
        log.error("CSV 형식 에러: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse<>(null, ex.getMessage()));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.error("존재하지 않는 리소스: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiResponse<>(null, ex.getMessage()));
    }
}
