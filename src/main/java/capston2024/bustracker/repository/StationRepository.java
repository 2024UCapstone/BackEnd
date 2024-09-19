package capston2024.bustracker.repository;

import capston2024.bustracker.domain.Station;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface StationRepository extends MongoRepository<Station, String> {
    // 특정 정류장을 정류장 이름으로 조회(정류장 이름은 중복 X <- DB에서 + 백에서 한번 더 검사)
    Optional<Station> findByName(String name);
}
