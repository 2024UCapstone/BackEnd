package capston2024.bustracker.domain;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Document(collection = "tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Token {
    @Id
    private String id;
    private String username;
    private String refreshToken;
    private String accessToken;
    @Indexed(expireAfterSeconds = 0)  // TTL 인덱스 설정
    private Date expirationDate;  // 만료 시간 필드 추가
}