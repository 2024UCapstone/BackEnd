package capston2024.bustracker.repository;

import capston2024.bustracker.domain.Station;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface MyStationRepository extends MongoRepository<Station, String> {
}
