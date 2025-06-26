package capston2024.bustracker.config.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class BusRegisterDTO {
    private String routeId;           // 라우트 ID (이전 stationNames 대신)
    private int totalSeats;           // 총 좌석 수
    private String busRealNumber;     // 실제 버스 번호 (운영자가 지정하는 번호)
    private boolean isOperate = true; // 운행 여부 (기본값: true)
}