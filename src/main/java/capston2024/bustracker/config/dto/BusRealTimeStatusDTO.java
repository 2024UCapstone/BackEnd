package capston2024.bustracker.config.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 클라이언트에게 전송할 버스 상태 정보 DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BusRealTimeStatusDTO {
    private String busId;
    private String busNumber;           // 버스 번호
    private String busRealNumber;       // 실제 버스 번호 (운영자가 지정하는 번호)
    private String routeName;           // 노선 이름
    private String organizationId;      // 조직 ID
    private double latitude;            // 위도
    private double longitude;           // 경도
    private int totalSeats;             // 총 좌석 수
    private int occupiedSeats;          // 사용 중인 좌석 수
    private int availableSeats;         // 사용 가능한 좌석 수
    private String currentStationName;  // 현재/마지막 정류장 이름
    private long lastUpdateTime;        // 마지막 업데이트 시간
    private int currentStationIndex;    // 현재 정류장 인덱스
    private int totalStations;          // 전체 정류장 수
    private boolean isOperate;          // 운행 여부
}