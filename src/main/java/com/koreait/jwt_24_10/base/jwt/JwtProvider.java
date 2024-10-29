package com.koreait.jwt_24_10.base.jwt;

import com.koreait.jwt_24_10.util.Ut;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Component
public class JwtProvider {
    private SecretKey cachedSecretKey;

    @Value("${custom.jwt.secretKey}")
    private String secretKeyPlain;

    private SecretKey _getSecretKey() {
        String keyBase64Encoded = Base64.getEncoder().encodeToString(secretKeyPlain.getBytes());

        return Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
    }

    public SecretKey getSecretKey() {
        if(cachedSecretKey == null) {
            cachedSecretKey = _getSecretKey();
        }

        return cachedSecretKey;
    }

    public String getToken(Map<String, Object> claims, int seconds) {
        long now = new Date().getTime();

        Date accessTokenExpiresIn = new Date(now + 1000L * seconds);

        return Jwts.builder()
                .claim("body", Ut.json.toStr(claims)) //claims의 내용을 str으로 바꿔서 body에 채워줌
                .setExpiration(accessTokenExpiresIn)
                .signWith(getSecretKey(), SignatureAlgorithm.HS512) //해시 알고리즘 종류
                .compact();
    }
    
    //토큰 하나 넘겨받으면, 해당 토큰이 유효한 놈인지 아닌지 판별해주는 함수
    public boolean verify(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSecretKey())
                    .build()
                    .parseClaimsJws(token);
        } catch(Exception e) {
            return false;
        }
        return true;
    }

    public Map<String, Object> getClaims(String token) {
        String body = Jwts.parserBuilder()
                .setSigningKey(getSecretKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("body", String.class);

        return Ut.json.toMap(body);
    }
}
