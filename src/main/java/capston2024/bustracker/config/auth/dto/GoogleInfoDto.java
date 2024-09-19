package capston2024.bustracker.config.auth.dto;

import capston2024.bustracker.domain.User;
import lombok.Getter;

import java.io.Serializable;

/**
 * 인증된 사용자 정보를 모아 놓는 클래스
 */
@Getter
public class GoogleInfoDto {
    private String name;
    private String email;
    private String picture;

    public GoogleInfoDto(User user) {
        this.name = user.getName();
        this.email = user.getEmail();
        this.picture = user.getPicture();
    }
}