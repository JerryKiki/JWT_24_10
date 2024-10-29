package com.koreait.jwt_24_10;

import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import javax.crypto.SecretKey;
import java.util.Base64;
import static org.assertj.core.api.Assertions.assertThat;
@SpringBootTest
class JwtTests {
    @Value("${custom.jwt.secretKey}")
    private String secretKeyPlain;
    @Test
    @DisplayName("secretKey가 존재 해야함")
    void t1() {
        assertThat(secretKeyPlain).isNotNull();
    }
    @Test
    @DisplayName("secretKey 원문으로 hmac 암호화 알고리즘에 맞는 SecretKey 객체를 만들 수 있다.")
    void t2() {
        // 키를 Base64 인코딩 한다.
        String keyBase64Encoded = Base64.getEncoder().encodeToString(secretKeyPlain.getBytes());
        // Base64 인코딩 된 키를 이용해서 SecretKey 객체를 만든다.
        SecretKey secretKey = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
        assertThat(secretKeyPlain).isNotNull();
    }
}
