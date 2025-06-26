package capston2024.bustracker.service;

import capston2024.bustracker.domain.Token;
import capston2024.bustracker.handler.JwtTokenProvider;
import capston2024.bustracker.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {
    private final TokenRepository tokenRepository;

    public void saveToken(String username, String refreshToken, String accessToken, Date expiration) {
        tokenRepository.findByUsername(username).ifPresent(tokenRepository::delete);
        Token tokenInfo = Token.builder()
                .username(username)
                .refreshToken(refreshToken)
                .accessToken(accessToken)
                .expirationDate(expiration)
                .build();
        tokenRepository.save(tokenInfo);
    }

    public Token findByAccessToken(String accessToken) {
        return tokenRepository.findByAccessToken(accessToken).orElse(null);
    }

    public Token findByUserName(String username){
        Optional<Token> token = tokenRepository.findByUsername(username);
        return token.orElse(null);
    }

    public void updateAccessToken(String username, String newAccessToken) {
        tokenRepository.findByUsername(username).ifPresent(tokenInfo -> {
            tokenInfo.setAccessToken(newAccessToken);
            // 액세스 토큰 만료 시간 업데이트
            Date newExpiration = new Date(System.currentTimeMillis() +
                    JwtTokenProvider.ACCESS_TOKEN_EXPIRE_TIME);
            tokenInfo.setExpirationDate(newExpiration);
            tokenRepository.save(tokenInfo);
        });
    }

    /**
     * 사용자 이름으로 토큰 정보 삭제
     * @param username 사용자 이름 (이메일)
     * @return 삭제 성공 여부
     */
    public boolean deleteByUsername(String username) {
        try {
            Optional<Token> tokenInfo = tokenRepository.findByUsername(username);
            if (tokenInfo.isPresent()) {
                tokenRepository.delete(tokenInfo.get());
                log.info("사용자 토큰 삭제 완료: {}", username);
                return true;
            } else {
                log.warn("삭제할 토큰 정보가 없습니다: {}", username);
                return false;
            }
        } catch (Exception e) {
            log.error("토큰 삭제 중 오류 발생: {}", e.getMessage(), e);
            return false;
        }
    }
}