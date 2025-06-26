package capston2024.bustracker.repository;

import capston2024.bustracker.domain.Token;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface TokenRepository extends MongoRepository<Token, String> {
    Optional<Token> findByAccessToken(String accessToken);
    Optional<Token> findByUsername(String username);
}
