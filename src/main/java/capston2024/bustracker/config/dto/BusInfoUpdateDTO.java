package capston2024.bustracker.config.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class BusInfoUpdateDTO {
    private String busNumber;       // 버스 번호 (3~6자리 고유 코드)
    private String busRealNumber;   // 실제 버스 번호 (운영자가 지정하는 번호)
    private String routeId;         // 라우트 ID
    private Integer totalSeats;      // 전체 좌석 수 (Integer로 변경)
    private Boolean isOperate;      // 운행 여부 (Boolean으로 null 허용)
}