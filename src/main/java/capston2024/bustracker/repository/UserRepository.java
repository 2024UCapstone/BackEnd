package capston2024.bustracker.repository;

import capston2024.bustracker.config.status.Role;
import capston2024.bustracker.domain.Auth;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * 데이터베이스에 접근, 도메인 객체를 DB에 저장하고 관리
 */
@Repository
public interface UserRepository extends MongoRepository<Auth, String> { //구글 로그인
    Optional<Auth> findByEmail(String email);

    List<Auth> findByOrganizationId(String organizationId);

    Auth findByIdAndOrganizationId(String id, String userOrganizationId);

    List<Auth> findByOrganizationIdAndRole(String organizationId, Role role);
}
