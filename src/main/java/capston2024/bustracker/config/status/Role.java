package capston2024.bustracker.config.status;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum Role {
    GUEST("ROLE_GUEST", "손님"), // 아직 기관 인증을 하지 않은 사용자
    USER("ROLE_USER", "일반 사용자"), // 기관 인증을 한 사용자
    STAFF("STAFF", "조직 관리자"),
    ADMIN("ADMIN", "관리자"); // 관리자

    private final String key;
    private final String title;
}
