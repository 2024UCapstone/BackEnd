package capston2024.bustracker.config.dto;

import lombok.*;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;

import java.time.Instant;

/**
 * 버스 기사 앱에서 전송하는 위치 업데이트용 DTO
 */
@Getter
@Setter
@RequiredArgsConstructor
public class BusRealTimeLocationDTO {
    private final String busNumber;           // 버스 번호
    private final String organizationId;      // 조직 ID
    private final  GeoJsonPoint location;
    private final int occupiedSeats;          // 현재 사용 중인 좌석 수
    private final Instant timestamp;             // 타임스탬프 (밀리초)
}