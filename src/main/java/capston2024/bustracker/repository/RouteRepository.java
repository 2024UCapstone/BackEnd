package capston2024.bustracker.repository;

import capston2024.bustracker.domain.Route;
import com.mongodb.DBRef;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RouteRepository extends MongoRepository<Route, String> {

    // 라우트 이름으로 조회
    Optional<Route> findByRouteName(String routeName);

    // 라우트 이름에 포함된 문자열과 조직 ID로 조회
    List<Route> findByRouteNameContainingIgnoreCaseAndOrganizationId(String routeName, String organizationId);

    // 조직 ID로 조회
    List<Route> findByOrganizationId(String organizationId);

    // 특정 정류장 ID를 포함하는 라우트 조회
    @Query("{'stations.stationId.$id': ?0}")
    List<Route> findByStationId(String stationId);

    // DBRef 객체로 정류장 조회
    List<Route> findByStationsStationId(DBRef stationRef);

    // 조직 ID와 라우트 이름으로 조회
    Optional<Route> findByOrganizationIdAndRouteName(String organizationId, String routeName);

    // 라우트 이름 존재 여부 확인
    boolean existsByRouteName(String routeName);

    Optional<Route> findByRouteNameAndOrganizationId(String routeName, String organizationId);
}