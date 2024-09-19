package capston2024.bustracker.exception;

import lombok.Getter;

@Getter
public enum ErrorCode {
    INVALID_TOKEN("Invalid token provided"),
    TOKEN_EXPIRED("Token has expired"),
    ACCESS_DENIED("Access denied"),
    USER_NOT_FOUND("User not found"),
    GENERAL_ERROR("A general error occurred");

    private final String message;

    ErrorCode(String message) {
        this.message = message;
    }

}
