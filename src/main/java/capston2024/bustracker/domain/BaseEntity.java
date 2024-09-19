package capston2024.bustracker.domain;

import lombok.Getter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.LocalDateTime;

@Getter
public abstract class BaseEntity {
    private LocalDateTime createdAt;
    private LocalDateTime updateAt;

    @CreatedDate
    public void prePersist(){
        this.createdAt = LocalDateTime.now();
        this.updateAt = LocalDateTime.now();
    }

    @LastModifiedDate
    public void preUpdate() {
        this.updateAt = LocalDateTime.now();
    }
}
