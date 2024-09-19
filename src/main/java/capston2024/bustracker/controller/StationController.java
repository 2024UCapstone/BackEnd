package capston2024.bustracker.controller;

import capston2024.bustracker.domain.Station;
import capston2024.bustracker.service.StationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
@Slf4j
public class StationController {

    private StationService stationService;

    public StationController(StationService stationService) {
        this.stationService = stationService;
    }

    // 특정 정류장 조회
    @GetMapping("/station")
    public String getStation(@RequestParam String name) {
        log.info("가져 올 버스정류장의 아이디: {}", name);
        Optional<Station> stations = stationService.getStation(name);

        if (stations.isEmpty()) {
            log.warn("Station not found with name: {}", name);
            return "false";
        }

        return "ok"; // 좌표 리스트 반환
    }

    // 모든 정류장 조회
    @GetMapping("/station/all")
    public List<Station> getAllStation() {
        log.info("클라이언트 요청: 모든 정류장 조회");
        List<Station> stations = stationService.getAllStations();
        log.info("조회된 정류장 수: {}", stations.size());  // 가져온 정류장 개수를 출력
        return stations;
    }
}