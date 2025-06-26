package capston2024.bustracker.repository;

import capston2024.bustracker.domain.Route;
import capston2024.bustracker.domain.Station;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface StationRepository extends MongoRepository<Station, String> {
    List<Station> findAllByOrganizationId(String organizationId);

    Optional<Station> findByNameAndOrganizationId(String stationName, String organizationId);
    // 특정 이름이 포함된 정류장 조회
    List<Station> findByNameContainingIgnoreCaseAndOrganizationId(String stationName, String organizationId);

    List<Station> findAllByIdIn(Collection<String> ids);
}
