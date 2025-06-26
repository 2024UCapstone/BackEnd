package capston2024.bustracker.config.dto;

import lombok.Data;

import java.util.List;

@Data
public class KakaoDirectionsResponse {
    private List<Route> routes;

    @Data
    public static class Route {
        private List<Section> sections;
        private Summary summary;
    }

    @Data
    public static class Section {
        private int distance;  // 구간 거리(미터)
        private int duration;  // 구간 소요 시간(초)
    }

    @Data
    public static class Summary {
        private int distance;  // 총 거리(미터)
        private int duration;  // 총 소요 시간(초) // 예상 소요 시간(초)
    }

    public int getDuration() {
        return routes.getFirst().getSummary().getDuration();
    }
}
