package capston2024.bustracker.controller;

import capston2024.bustracker.config.auth.dto.GoogleInfoDto;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Objects;

/**
 * ** 웹 MVC의 컨트롤러 역할 **
 * 계정 정보 유효성 검사
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @GetMapping("/login")
    public void login(HttpServletResponse response) throws IOException, java.io.IOException {
        response.sendRedirect("/oauth2/authorization/google");
    }

    @GetMapping("/oauth2/code/google")
    public ResponseEntity<GoogleInfoDto> googleCallback(@AuthenticationPrincipal OAuth2User oAuth2User) {
        GoogleInfoDto userInfo = new GoogleInfoDto(Objects.requireNonNull(oAuth2User.getAttribute("user")));
        return ResponseEntity.ok(userInfo);
    }

    @GetMapping("/loginInfo")
    public String oauthLoginInfo(@AuthenticationPrincipal OAuth2User oAuth2User) {
        if (oAuth2User == null) {
            return "User not authenticated";
        }
        //oAuth2User.toString() 예시 : Name: [2346930276], Granted Authorities: [[USER]], User Attributes: [{id=2346930276, provider=kakao, name=김준우, email=bababoll@naver.com}]
        //attributes.toString() 예시 : {id=2346930276, provider=kakao, name=김준우, email=bababoll@naver.com}
        Map<String, Object> attributes = oAuth2User.getAttributes();
        return attributes.toString();
    }

    @GetMapping("/user")
    public ResponseEntity<GoogleInfoDto> getUser(@AuthenticationPrincipal OAuth2User oAuth2User) {
        if (oAuth2User == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        GoogleInfoDto userInfo = new GoogleInfoDto(Objects.requireNonNull(oAuth2User.getAttribute("user")));

        return ResponseEntity.ok(userInfo);
    }
    @GetMapping("/logout")
    public ResponseEntity<Void> logout() {
        // JWT는 stateless이므로 서버에서 특별히 할 일은 없습니다.
        // 클라이언트에서 토큰을 삭제하도록 안내합니다.
        return ResponseEntity.ok().build();
    }
}