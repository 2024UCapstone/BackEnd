package capston2024.bustracker.repository;

import capston2024.bustracker.domain.Bus;
import capston2024.bustracker.domain.Station;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

public interface BusRepository extends MongoRepository<Bus, String> {
    Optional<Bus> findByIdOrderByTimestampDesc(String id); // 버스 아이디로 버스 조회
    Optional<Bus> findBusByBusNumber(String busNumber);
    boolean existsBusByBusNumber(String busNumber); // 버스 번호 중복 감지
    List<Bus> findByStationsContaining(Station station);
}
