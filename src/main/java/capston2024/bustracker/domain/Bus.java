package capston2024.bustracker.domain;

import com.mongodb.DBRef;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.List;

@Document(collection = "bus")
@Getter @Setter
@AllArgsConstructor // 모든 필드를 받는 생성자 생성
@NoArgsConstructor // 기본 생성자 생성
@Builder
@CompoundIndex(def = "{'location': '2dsphere'}")
public class Bus {

    @Id
    private String id; // MongoDB에서 자동 생성될 _id

    @Indexed(unique = true)
    private String busNumber; // 버스 ID에서 추출한 고유 번호 (3~6자리)

    private String busRealNumber; // 실제 버스 번호 (운영자가 지정하는 번호)

    @NonNull
    private String organizationId; // 조직 ID (필수)

    private int totalSeats; // 전체 좌석
    private int occupiedSeats; // 앉은 좌석 수
    private int availableSeats; // 남은 좌석 수
    private GeoJsonPoint location; // 좌표 정보 (GeoJSON 형식)
    private DBRef routeId; // 버스의 노선(정류장들의 DBRef)
    private Instant timestamp; // 위치 정보 최신화

    // 추가되는 필드들
    private String prevStationId;  // 현재/마지막으로 지난 정류장 ID
    private Instant lastStationTime;  // 마지막 정류장 통과 시간
    private int prevStationIdx;  // 현재 정류장의 순서 (stations 리스트상의 인덱스)

    // 새로 추가된 필드
    private boolean isOperate; // 운행 여부 (true: 운행 중, false: 운행 중지)

    @Override
    public String toString() {
        return "Bus{" +
                "id='" + id + '\'' +
                ", busNumber='" + busNumber + '\'' +
                ", busRealNumber='" + busRealNumber + '\'' +
                ", organizationId='" + organizationId + '\'' +
                ", location=" + location +
                ", timestamp=" + timestamp +
                ", isOperate=" + isOperate +
                '}';
    }
}