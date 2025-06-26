package capston2024.bustracker.util;

import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

/**
 * Bus ID에서 고유한 버스 번호를 생성하는 유틸리티 클래스
 */
@Component
public class BusNumberGenerator {

    /**
     * Bus ID와 조직 ID를 기반으로 3~6자리의 고유한 버스 번호를 생성합니다.
     *
     * @param busId Bus 객체의 ID
     * @param organizationId 조직 ID
     * @return 3~6자리의 고유한 버스 번호
     */
    public String generateBusNumber(String busId, String organizationId) {
        try {
            // busId와 organizationId를 조합하여 해시 생성
            String combined = busId + "_" + organizationId;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(combined.getBytes());

            // Base64 인코딩
            String base64 = Base64.getUrlEncoder().encodeToString(hash);

            // 숫자와 대문자로 구성된 문자열 생성 (3~6자리)
            StringBuilder result = new StringBuilder();
            int length = 4 + (Math.abs(busId.hashCode()) % 3); // 3~6자리 길이 결정

            for (int i = 0; i < base64.length() && result.length() < length; i++) {
                char c = base64.charAt(i);
                if (Character.isDigit(c)) {
                    result.append(c);
                } else if (Character.isLetter(c)) {
                    // 문자를 숫자로 변환 (A-Z -> 1-26)
                    result.append(Math.abs((Character.toUpperCase(c) - 'A') % 10));
                }
            }

            // 결과가 너무 짧으면 앞에 조직 ID의 해시값 추가
            if (result.length() < 3) {
                int orgHash = Math.abs(organizationId.hashCode() % 1000);
                result.insert(0, String.format("%03d", orgHash));
            }

            // 길이 제한 (3~6자리)
            if (result.length() > 6) {
                return result.substring(0, 6);
            }

            return result.toString();

        } catch (NoSuchAlgorithmException e) {
            // 해시 알고리즘이 지원되지 않는 경우 간단한 폴백 메커니즘 사용
            String simpleHash = String.valueOf(Math.abs((busId + organizationId).hashCode()));
            return simpleHash.substring(0, Math.min(simpleHash.length(), 6));
        }
    }

    /**
     * 특정 조직 내에서 버스 번호가 중복되지 않는지 확인합니다.
     *
     * @param busNumber 확인할 버스 번호
     * @param existingNumbers 기존 버스 번호 목록
     * @return 중복 여부 (true: 중복 없음, false: 중복 있음)
     */
    public boolean isUniqueInOrganization(String busNumber, List<String> existingNumbers) {
        return !existingNumbers.contains(busNumber);
    }
}