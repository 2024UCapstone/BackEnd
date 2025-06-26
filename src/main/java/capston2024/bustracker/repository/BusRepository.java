package capston2024.bustracker.repository;

import capston2024.bustracker.domain.Bus;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface BusRepository extends MongoRepository<Bus, String> {
    Optional<Bus> findByIdOrderByTimestampDesc(String id); // 버스 아이디로 버스 조회
    Optional<Bus> findBusByBusNumber(String busNumber);
    boolean existsBusByBusNumber(String busNumber); // 버스 번호 중복 감지

    // 조직 ID로 버스 조회
    List<Bus> findByOrganizationId(String organizationId);

    // 버스 번호와 조직 ID로 버스 조회
    Optional<Bus> findByBusNumberAndOrganizationId(String busNumber, String organizationId);

    // 실제 버스 번호와 조직 ID로 버스 조회
    Optional<Bus> findByBusRealNumberAndOrganizationId(String busRealNumber, String organizationId);

    // 실제 버스 번호 중복 체크 (조직 내)
    boolean existsByBusRealNumberAndOrganizationId(String busRealNumber, String organizationId);

    // 운행 상태별 조회
    List<Bus> findByOrganizationIdAndIsOperateTrue(String organizationId);
    List<Bus> findByOrganizationIdAndIsOperateFalse(String organizationId);
    // 라우트 ID로 버스 조회
    @Query("{'routeId.$id': ?0}")
    List<Bus> findByRouteId(String routeId);

    // 운행 상태별 버스 조회
    List<Bus> findByOrganizationIdAndIsOperate(String organizationId, boolean isOperate);

    long countByOrganizationIdAndIsOperateTrue(String organizationId);
    long countByIsOperateTrue(); // 전체 운행 중인 버스 수
}