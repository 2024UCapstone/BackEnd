package capston2024.bustracker.config.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class RouteDTO {
    private String id;
    private String routeName;
    private String organizationId;
    private List<RouteStationDTO> stations;

    @Getter @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RouteStationDTO {
        private int sequence;
        private String stationId;
        private String stationName; // 클라이언트에 표시할 정류장 이름
    }
}