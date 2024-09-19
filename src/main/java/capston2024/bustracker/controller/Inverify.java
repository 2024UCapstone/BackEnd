package capston2024.bustracker.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Inverify {
    @PostMapping("/api/inverify") // 해당 학교의 접근 코드(uid)
    public boolean getVerifySchoolCode(){ //학교정보코드 조회
        //불러온 학교 코드를 검사하여 해당 학교의 유효성 검사
        return true;
    }

}
