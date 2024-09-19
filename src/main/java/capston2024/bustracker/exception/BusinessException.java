package capston2024.bustracker.exception;

import lombok.Getter;

@Getter
public class BusinessException extends RuntimeException {

    // 에러 코드 반환
    private final ErrorCode errorCode;

    // 기본 메시지를 가진 생성자
    public BusinessException(String message) {
        super(message);
        this.errorCode = ErrorCode.GENERAL_ERROR;
    }

    // 에러 코드와 메시지를 가진 생성자
    public BusinessException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    // 에러 코드를 가진 생성자
    public BusinessException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

}
