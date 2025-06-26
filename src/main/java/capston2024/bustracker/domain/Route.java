package capston2024.bustracker.domain;

import com.mongodb.DBRef;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;
import java.util.List;

@Document(collection = "routes")
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Route {

    @Id
    private String id;

    private String routeName;

    private String organizationId;

    private List<RouteStation> stations;

    @CreatedDate
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RouteStation {
        private int sequence;
        private DBRef stationId;
    }
}