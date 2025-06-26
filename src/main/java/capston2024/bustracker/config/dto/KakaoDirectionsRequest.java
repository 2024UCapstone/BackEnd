package capston2024.bustracker.config.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class KakaoDirectionsRequest {
    private KakaoPoint origin;
    private KakaoPoint destination;
    private List<KakaoPoint> waypoints;
    private String priority;  // "TIME" or "DISTANCE"
}

