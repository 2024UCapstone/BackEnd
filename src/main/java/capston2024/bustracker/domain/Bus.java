package capston2024.bustracker.domain;

import com.mongodb.DBRef;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.List;

@Document(collection = "Bus")
@Getter @Setter
@AllArgsConstructor // 모든 필드를 받는 생성자 생성
@NoArgsConstructor // 기본 생성자 생성
@Builder
@CompoundIndex(def = "{'location': '2dsphere'}")
public class Bus {

    @Id
    private String id; // MongoDB에서 자동 생성될 _id
    private String busNumber;
    private int totalSeats; // 전체 좌석
    private int occupiedSeats; // 앉은 좌석 수
    private int availableSeats; // 남은 좌석 수
    private GeoJsonPoint location; // 좌표 정보 (GeoJSON 형식)
    private List<StationInfo> stations; // 버스의 노선(정류장들의 DBRef)
    private Instant timestamp; // 위치 정보 최신화
    @Override
    public String toString() {
        return "Bus{" +
                "id='" + id + '\'' +
                ", busNumber='" + busNumber + '\'' +
                ", location=" + location +
                ", timestamp=" + timestamp +
                '}';
    }

    @Data
    @AllArgsConstructor
    public static class StationInfo {
        private DBRef stationRef;
        private String stationName;
    }
}
