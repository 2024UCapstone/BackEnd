package capston2024.bustracker.service;

import capston2024.bustracker.domain.auth.TokenInfo;
import capston2024.bustracker.handler.JwtTokenProvider;
import capston2024.bustracker.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final TokenRepository tokenRepository;

    public void saveToken(String username, String refreshToken, String accessToken, Date expiration) {
        tokenRepository.findByUsername(username).ifPresent(tokenRepository::delete);
        TokenInfo tokenInfo = TokenInfo.builder()
                .username(username)
                .refreshToken(refreshToken)
                .accessToken(accessToken)
                .expirationDate(expiration)
                .build();
        tokenRepository.save(tokenInfo);
    }

    public TokenInfo findByAccessToken(String accessToken) {
        return tokenRepository.findByAccessToken(accessToken).orElse(null);
    }

    public TokenInfo findByUserName(String username){
        Optional<TokenInfo> token = tokenRepository.findByUsername(username);
        return token.orElse(null);
    }
    public void updateAccessToken(String username, String newAccessToken) {
        tokenRepository.findByUsername(username).ifPresent(tokenInfo -> {
            tokenInfo.setAccessToken(newAccessToken);
            // 액세스 토큰 만료 시간 업데이트
            Date newExpiration = new Date(System.currentTimeMillis() +
                    JwtTokenProvider.ACCESS_TOKEN_EXPIRE_TIME);
            tokenInfo.setExpirationDate(newExpiration);
        });

    }
}