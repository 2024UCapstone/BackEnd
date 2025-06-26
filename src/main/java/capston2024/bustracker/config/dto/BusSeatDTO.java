package capston2024.bustracker.config.dto;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class BusSeatDTO {
    private String busNumber;         // 버스 번호
    private String busRealNumber;     // 실제 버스 번호 (운영자가 지정하는 번호)
    private int totalSeats;
    private int availableSeats;
    private int occupiedSeats;
    private boolean isOperate;        // 운행 여부
}