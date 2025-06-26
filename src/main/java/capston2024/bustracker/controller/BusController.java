package capston2024.bustracker.controller;

import capston2024.bustracker.config.dto.*;
import capston2024.bustracker.domain.Bus;
import capston2024.bustracker.domain.Station;
import capston2024.bustracker.exception.BusinessException;
import capston2024.bustracker.exception.ResourceNotFoundException;
import capston2024.bustracker.exception.UnauthorizedException;
import capston2024.bustracker.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

// Swagger 어노테이션 추가
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/bus")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Bus", description = "버스 관리 관련 API")
public class BusController {

    private final BusService busService;
    private final AuthService authService;

    /**
     * 버스 추가
     */
    @PostMapping()
    @PreAuthorize("hasRole('STAFF')")
    @Operation(summary = "버스 등록",
            description = "새로운 버스를 등록합니다. 관리자 권한이 필요합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "버스 등록 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "잘못된 요청 데이터"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "권한 없음 (관리자 권한 필요)")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<String>> createBus(
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal,
            @Parameter(description = "버스 등록 요청 데이터") @RequestBody BusRegisterDTO busRegisterDTO) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 버스를 등록할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 버스를 등록할 수 없습니다.");
        }

        log.info("버스 등록 요청 - 조직: {}, 노선: {}", organizationId, busRegisterDTO.getRouteId());
        String busNumber = busService.createBus(busRegisterDTO, organizationId);

        return ResponseEntity.ok(new ApiResponse<>(busNumber, "성공적으로 버스가 추가되었습니다."));
    }

    /**
     * 버스 삭제
     */
    @DeleteMapping("/{busNumber}")
    @PreAuthorize("hasRole('STAFF')")
    @Operation(summary = "버스 삭제",
            description = "지정된 버스 번호의 버스를 삭제합니다. 관리자 권한이 필요합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "버스 삭제 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "권한 없음 (관리자 권한 필요)"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "버스를 찾을 수 없음")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<Boolean>> deleteBus(
            @Parameter(description = "삭제할 버스 번호") @PathVariable String busNumber,
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 버스를 삭제할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 버스를 삭제할 수 없습니다.");
        }

        log.info("버스 삭제 요청 - 버스 번호: {}, 조직: {}", busNumber, organizationId);
        boolean result = busService.removeBus(busNumber, organizationId);

        return ResponseEntity.ok(new ApiResponse<>(result, "성공적으로 버스가 삭제되었습니다."));
    }

    /**
     * 버스 수정
     */
    @PutMapping()
    @PreAuthorize("hasRole('STAFF')")
    @Operation(summary = "버스 정보 수정",
            description = "버스의 정보를 수정합니다. 관리자 권한이 필요합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "버스 정보 수정 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "잘못된 요청 데이터"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "권한 없음 (관리자 권한 필요)"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "버스를 찾을 수 없음")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<Boolean>> updateBus(
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal,
            @Parameter(description = "버스 정보 수정 요청 데이터") @RequestBody BusInfoUpdateDTO busInfoUpdateDTO) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 버스를 수정할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 버스를 수정할 수 없습니다.");
        }

        if (busInfoUpdateDTO.getBusNumber() == null || busInfoUpdateDTO.getBusNumber().trim().isEmpty()) {
            throw new BusinessException("버스 번호는 필수입니다.");
        }

        log.info("버스 수정 요청 - 버스 번호: {}, 조직: {}", busInfoUpdateDTO.getBusNumber(), organizationId);
        boolean result = busService.modifyBus(busInfoUpdateDTO, organizationId);

        return ResponseEntity.ok(new ApiResponse<>(result, "버스가 성공적으로 수정되었습니다."));
    }

    /**
     * 조직별 모든 버스 조회
     */
    @GetMapping()
    @Operation(summary = "조직별 모든 버스 조회",
            description = "현재 사용자가 속한 조직의 모든 버스 목록을 조회합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "버스 목록 조회 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<List<BusRealTimeStatusDTO>>> getAllBuses(
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 버스를 조회할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 버스를 조회할 수 없습니다.");
        }

        log.info("조직별 버스 목록 조회 요청 - 조직: {}", organizationId);
        List<BusRealTimeStatusDTO> buses = busService.getAllBusStatusByOrganizationId(organizationId);

        return ResponseEntity.ok(new ApiResponse<>(buses, "모든 버스가 성공적으로 조회되었습니다."));
    }

    /**
     * 특정 버스 조회
     */
    @GetMapping("/{busNumber}")
    @Operation(summary = "특정 버스 조회",
            description = "지정된 버스 번호의 버스 상세 정보를 조회합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "버스 조회 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "버스를 찾을 수 없음")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<BusRealTimeStatusDTO>> getBusByNumber(
            @Parameter(description = "조회할 버스 번호") @PathVariable String busNumber,
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 버스를 조회할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 버스를 조회할 수 없습니다.");
        }

        log.info("특정 버스 조회 요청 - 버스 번호: {}, 조직: {}", busNumber, organizationId);
        Bus bus = busService.getBusByNumberAndOrganization(busNumber, organizationId);
        List<BusRealTimeStatusDTO> allBuses = busService.getAllBusStatusByOrganizationId(organizationId);

        BusRealTimeStatusDTO busStatus = allBuses.stream()
                .filter(dto -> dto.getBusNumber().equals(busNumber))
                .findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("버스를 찾을 수 없습니다: " + busNumber));

        return ResponseEntity.ok(new ApiResponse<>(busStatus, "버스가 성공적으로 조회되었습니다."));
    }

    /**
     * 특정 정류장을 경유하는 버스 조회
     */
    @GetMapping("/station/{stationId}")
    @Operation(summary = "특정 정류장 경유 버스 조회",
            description = "지정된 정류장을 경유하는 모든 버스 목록을 조회합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "경유 버스 목록 조회 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "정류장을 찾을 수 없음")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<List<BusRealTimeStatusDTO>>> getBusesByStation(
            @Parameter(description = "정류장 ID") @PathVariable String stationId,
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 버스를 조회할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 버스를 조회할 수 없습니다.");
        }

        log.info("특정 정류장 경유 버스 조회 요청 - 정류장 ID: {}, 조직: {}", stationId, organizationId);
        List<BusRealTimeStatusDTO> buses = busService.getBusesByStationAndOrganization(stationId, organizationId);

        return ResponseEntity.ok(new ApiResponse<>(buses, "정류장을 경유하는 버스가 성공적으로 조회되었습니다."));
    }

    /**
     * 버스 정류장 상세 목록 조회
     */
    @GetMapping("/stations-detail/{busNumber}")
    @Operation(summary = "버스 정류장 상세 목록 조회",
            description = "지정된 버스의 모든 정류장 상세 정보를 조회합니다. 각 정류장의 통과 상태와 도착 예정 시간을 포함합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "버스 정류장 상세 목록 조회 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "버스를 찾을 수 없음")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<List<Station>>> getBusStationsDetail(
            @Parameter(description = "버스 번호") @PathVariable String busNumber,
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 정류장 목록을 조회할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 정류장 목록을 조회할 수 없습니다.");
        }

        List<Station> stationList = busService.getBusStationsDetail(busNumber, organizationId);

        return ResponseEntity.ok(new ApiResponse<>(stationList, "버스 정류장 상세 목록이 성공적으로 조회되었습니다."));
    }

    /**
     * 버스 좌석 조회
     */
    @GetMapping("/seats/{busNumber}")
    @Operation(summary = "버스 좌석 정보 조회",
            description = "지정된 버스의 좌석 정보를 조회합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "버스 좌석 정보 조회 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "버스를 찾을 수 없음")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<BusSeatDTO>> getBusSeatsByBusNumber(
            @Parameter(description = "버스 번호") @PathVariable String busNumber,
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 좌석 정보를 조회할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 좌석 정보를 조회할 수 없습니다.");
        }

        log.info("버스 좌석 조회 요청 - 버스 번호: {}, 조직: {}", busNumber, organizationId);
        BusSeatDTO seats = busService.getBusSeatsByBusNumber(busNumber, organizationId);

        return ResponseEntity.ok(new ApiResponse<>(seats, "좌석이 성공적으로 반환되었습니다."));
    }

    /**
     * 버스 위치 조회
     */
    @GetMapping("/location/{busNumber}")
    @Operation(summary = "버스 위치 정보 조회",
            description = "지정된 버스의 현재 위치 정보를 조회합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "버스 위치 정보 조회 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "버스를 찾을 수 없음")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<LocationDTO>> getBusLocationByBusNumber(
            @Parameter(description = "버스 번호") @PathVariable String busNumber,
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 위치 정보를 조회할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 위치 정보를 조회할 수 없습니다.");
        }

        log.info("버스 위치 조회 요청 - 버스 번호: {}, 조직: {}", busNumber, organizationId);
        LocationDTO locations = busService.getBusLocationByBusNumber(busNumber, organizationId);

        return ResponseEntity.ok(new ApiResponse<>(locations, "좌표 정보가 성공적으로 반환되었습니다."));
    }

    /**
     * 실제 버스 번호로 버스 조회
     */
    @GetMapping("/real-number/{busRealNumber}")
    @Operation(summary = "실제 버스 번호로 버스 조회",
            description = "운영자가 지정한 실제 버스 번호로 버스를 조회합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "버스 조회 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "버스를 찾을 수 없음")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<BusRealTimeStatusDTO>> getBusByRealNumber(
            @Parameter(description = "실제 버스 번호") @PathVariable String busRealNumber,
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 버스를 조회할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 버스를 조회할 수 없습니다.");
        }

        log.info("실제 버스 번호로 버스 조회 요청 - 실제 번호: {}, 조직: {}", busRealNumber, organizationId);

        Bus bus = busService.getBusByRealNumberAndOrganization(busRealNumber, organizationId);
        List<BusRealTimeStatusDTO> allBuses = busService.getAllBusStatusByOrganizationId(organizationId);

        BusRealTimeStatusDTO busStatus = allBuses.stream()
                .filter(dto -> dto.getBusRealNumber() != null && dto.getBusRealNumber().equals(busRealNumber))
                .findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("실제 버스 번호로 버스를 찾을 수 없습니다: " + busRealNumber));

        return ResponseEntity.ok(new ApiResponse<>(busStatus, "버스가 성공적으로 조회되었습니다."));
    }

    /**
     * 운행 중인 버스만 조회
     */
    @GetMapping("/operating")
    @Operation(summary = "운행 중인 버스 조회",
            description = "현재 운행 중인 상태의 버스만 조회합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "운행 중인 버스 목록 조회 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<List<BusRealTimeStatusDTO>>> getOperatingBuses(
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 버스를 조회할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 버스를 조회할 수 없습니다.");
        }

        log.info("운행 중인 버스 목록 조회 요청 - 조직: {}", organizationId);
        List<BusRealTimeStatusDTO> operatingBuses = busService.getOperatingBusesByOrganizationId(organizationId);

        return ResponseEntity.ok(new ApiResponse<>(operatingBuses, "운행 중인 버스가 성공적으로 조회되었습니다."));
    }

    /**
     * 버스 운행 상태 변경
     */
    @PutMapping("/{busNumber}/operate")
    @PreAuthorize("hasRole('STAFF')")
    @Operation(summary = "버스 운행 상태 변경",
            description = "버스의 운행 상태를 시작 또는 중지로 변경합니다. 관리자 권한이 필요합니다.")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "버스 운행 상태 변경 성공",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "권한 없음 (관리자 권한 필요)"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "버스를 찾을 수 없음")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ApiResponse<Boolean>> toggleBusOperation(
            @Parameter(description = "버스 번호") @PathVariable String busNumber,
            @Parameter(description = "운행 상태 (true: 운행 시작, false: 운행 중지)") @RequestParam boolean isOperate,
            @Parameter(hidden = true) @AuthenticationPrincipal OAuth2User principal) {

        if (principal == null) {
            throw new UnauthorizedException("인증된 사용자만 버스 운행 상태를 변경할 수 있습니다.");
        }

        Map<String, Object> userInfo = authService.getUserDetails(principal);
        String organizationId = (String) userInfo.get("organizationId");

        if (organizationId == null || organizationId.isEmpty()) {
            throw new BusinessException("조직에 속하지 않은 사용자는 버스 운행 상태를 변경할 수 없습니다.");
        }

        log.info("버스 운행 상태 변경 요청 - 버스 번호: {}, 조직: {}, 운행상태: {}", busNumber, organizationId, isOperate);

        BusInfoUpdateDTO updateDTO = new BusInfoUpdateDTO();
        updateDTO.setBusNumber(busNumber);
        updateDTO.setIsOperate(isOperate);

        boolean result = busService.modifyBus(updateDTO, organizationId);

        String message = isOperate ? "버스 운행이 시작되었습니다." : "버스 운행이 중지되었습니다.";
        return ResponseEntity.ok(new ApiResponse<>(result, message));
    }

    /**
     * 비즈니스 로직 예외 처리
     */
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadRequestException(BusinessException ex) {
        log.error("비지니스 서비스 로직 예외: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse<>(null, ex.getMessage()));
    }

    /**
     * 인증 예외 처리
     */
    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ApiResponse<Void>> handleUnauthorizedException(UnauthorizedException ex) {
        log.error("인가되지 않은 리소스: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse<>(null, ex.getMessage()));
    }

    /**
     * 리소스 찾을 수 없음 예외 처리
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.error("존재하지 않는 리소스: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiResponse<>(null, ex.getMessage()));
    }

    /**
     * 일반 예외 처리
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneralException(Exception ex) {
        log.error("일반 예외 발생: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiResponse<>(null, "서버 오류가 발생했습니다."));
    }
}