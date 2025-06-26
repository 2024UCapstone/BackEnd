package capston2024.bustracker.config.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 승객 탑승/하차 정보를 위한 DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BusBoardingDTO {
    private String busNumber;           // 버스 번호
    private String organizationId;      // 조직 ID
    private String userId;              // 사용자 ID
    private BoardingAction action;      // 탑승/하차 액션
    private long timestamp;             // 타임스탬프 (밀리초)

    public enum BoardingAction {
        BOARD,      // 탑승
        ALIGHT      // 하차
    }
}