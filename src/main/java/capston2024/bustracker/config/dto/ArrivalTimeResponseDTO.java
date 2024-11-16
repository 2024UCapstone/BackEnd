package capston2024.bustracker.config.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@Setter
@AllArgsConstructor
public class ArrivalTimeResponseDTO {
    private String name;
    private String durationMessage;  // 도착까지의 총 소요 시간 (시 분 초 형식)
}
