package capston2024.bustracker.domain;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;

@Document(collection = "Bus")
@Getter @Setter
public class Bus {

    @Id
    private String id; // MongoDB에서 자동 생성될 _id
    private int seat;
    private String startTime; // 문자열로 시간 저장 (HH:mm 형식)
    private GeoJsonPoint location; // 좌표 정보 (GeoJSON 형식)

    // 기본 생성자
    public Bus() {}

    // 매개변수 생성자
    public Bus(int seat, String startTime, GeoJsonPoint location) {
        this.seat = seat;
        this.startTime = startTime;
        this.location = location;
    }
}
