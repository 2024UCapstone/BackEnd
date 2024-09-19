package capston2024.bustracker.repository;

import capston2024.bustracker.domain.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * 데이터베이스에 접근, 도메인 객체를 DB에 저장하고 관리
 */
@Repository
public interface UserRepository extends MongoRepository<User, String> { //구글 로그인
    Optional<User> findByEmail(String email);
}
