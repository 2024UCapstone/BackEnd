package capston2024.bustracker.config.dto;

import lombok.Data;

@Data
public class KakaoPoint {
    private double x;  // longitude
    private double y;  // latitude

    public KakaoPoint(double x, double y) {
        this.x = x;
        this.y = y;
    }
}
