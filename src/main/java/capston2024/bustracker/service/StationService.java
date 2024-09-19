package capston2024.bustracker.service;

import capston2024.bustracker.domain.Station;
import capston2024.bustracker.repository.StationRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@Slf4j
public class StationService {

    private final StationRepository stationRepository;

    // 생성자 주입 방식
    public StationService(StationRepository stationRepository) {
        this.stationRepository = stationRepository;
    }

    // 특정 id에 해당하는 정류장의 좌표를 가져옴
    public Optional<Station> getStation(String name) {
        log.info("station finding....");
        return stationRepository.findByName(name);
    }

    // 모든 정류장을 가져옴
    public List<Station> getAllStations() {
        log.info("MongoDB에서 데이터를 불러들이는 중...");
        return stationRepository.findAll();
    }
}
