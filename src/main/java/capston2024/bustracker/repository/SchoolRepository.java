package capston2024.bustracker.repository;

import capston2024.bustracker.domain.BusCoordinate;
import capston2024.bustracker.domain.BusStopCoordinate;
import capston2024.bustracker.domain.School;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface SchoolRepository extends MongoRepository<School, String> {
}
