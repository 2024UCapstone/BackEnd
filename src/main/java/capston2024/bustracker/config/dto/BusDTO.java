package capston2024.bustracker.config.dto;

import lombok.Getter;
import lombok.Setter;
import org.bson.types.ObjectId;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;

import java.time.Instant;
import java.util.List;

@Getter
@Setter
public class BusDTO {
    private String id; // mongoDB에서 생성되는 id
    private String busNumber;
    private int totalSeats; // 전체 좌석
    private List<String> stationNames; // 버스의 노선(정류장 이름 목록)
}
