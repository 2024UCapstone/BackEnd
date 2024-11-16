package capston2024.bustracker.config.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;

import java.time.Instant;

/**
 * 버스 위치, 좌석 정보 처리 DTO
 */
@RequiredArgsConstructor
@Getter
@Setter
public class BusUpdateDTO {
    private final String busNumber;
    private final GeoJsonPoint location;
    private final Instant timestamp;
    private final int seats;
}