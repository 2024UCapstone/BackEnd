package capston2024.bustracker.domain;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.geo.GeoJsonPoint;

@Document(collection = "station")
@Getter @Setter
@AllArgsConstructor // 모든 필드를 받는 생성자 생성
@NoArgsConstructor  // 기본 생성자 생성
@Builder
public class Station {

    @Id
    private String id;
    private String name;
    private GeoJsonPoint location;
    private String organizationId;

    // 이 필드들은 DB에 저장되지 않고 API 응답에만 사용됨
    @Transient
    private Boolean isPassed;

    @Transient
    private Boolean isCurrentStation;

    @Transient
    private String estimatedArrivalTime;

    @Transient
    private Integer sequence;

    public Boolean isPassed() {
        return isPassed != null && isPassed;
    }

    public Boolean isCurrentStation() {
        return isCurrentStation != null && isCurrentStation;
    }

    public void setPassed(boolean passed) {
        this.isPassed = passed;
    }

    public void setCurrentStation(boolean currentStation) {
        this.isCurrentStation = currentStation;
    }

    @Override
    public String toString() {
        return "Station{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", location=" + location +
                ", organizationId='" + organizationId + '\'' +
                ", sequence=" + sequence +
                ", isPassed=" + isPassed +
                ", isCurrentStation=" + isCurrentStation +
                '}';
    }
}