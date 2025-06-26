package capston2024.bustracker.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class OrganizationCodeGenerator {

    public static String generateOrganizationCode(String organizationName) {
        // 1. 공백 제거 및 소문자 변환
        String trimmedName = organizationName.trim().toLowerCase();

        // 2. SHA-256 해시 생성
        String hashedName = hashString(trimmedName);

        // 3. Base64 인코딩 및 처음 8자만 사용
        return Base64.getUrlEncoder().encodeToString(hashedName.getBytes()).substring(0, 8);
    }

    private static String hashString(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 알고리즘을 찾을 수 없습니다.", e);
        }
    }
}