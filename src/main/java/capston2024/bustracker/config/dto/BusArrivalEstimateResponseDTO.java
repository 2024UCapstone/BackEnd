package capston2024.bustracker.config.dto;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Data
@Builder
@Getter
@Setter
public class BusArrivalEstimateResponseDTO {
    private String estimatedTime;
    private List<String> waypoints;
}
