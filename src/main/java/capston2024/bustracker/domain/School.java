package capston2024.bustracker.domain;

import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "School")
public class School {
    private String code;
    private String name;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
