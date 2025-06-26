package capston2024.bustracker.util.auth;

import capston2024.bustracker.config.status.Role;
import capston2024.bustracker.domain.Auth;
import com.mongodb.DBRef;

import java.util.ArrayList;
import java.util.List;

/**
 *  처음 가입 시 엔티티 부여
 */
public class UserCreator {

    public static Auth createUserFrom(OAuthAttributes attributes) {
        List<DBRef> list = new ArrayList<>();
        return Auth.builder()
                .name(attributes.getName())
                .email(attributes.getEmail())
                .picture(attributes.getPicture())
                .myStations(list)
                .role(Role.GUEST)
                .build();
    }
}