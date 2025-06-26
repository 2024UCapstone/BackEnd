package capston2024.bustracker.domain;

import lombok.*;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "organization")
@Getter
@Setter
@AllArgsConstructor // 모든 필드를 받는 생성자 생성
@NoArgsConstructor // 기본 생성자 생성
@Builder
public class Organization {
    private String id;
    private String name;
}
