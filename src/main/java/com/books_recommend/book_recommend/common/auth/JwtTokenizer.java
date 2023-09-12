package com.books_recommend.book_recommend.common.auth;

//토큰을 생성하고 검증하는 클래스
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

public class JwtTokenizer {
    public String encodeBase64SecretKey(String secretKey) {
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Map<String, Object> claims, //인증된 사용자에게 JWT를 최초 발급
                                      String subject,
                                      Date expiration,
                                      String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
            .setClaims(claims) //JWT에 포함시킬 Custom Claims / 사용자와 관련된 정보
            .setSubject(subject) //JWT에 대한 제목
            .setIssuedAt(Calendar.getInstance().getTime()) //JWT 발행 일자 / 파라미터 타입 java.util.Date
            .setExpiration(expiration) //JWT 만료일시
            .signWith(key) //signature 을 위한 Key 객체 설정
            .compact();
    }

    public String generateRefreshToken(String subject, Date expiration, String base64EncodedSecretKey) { //Refresh Token 생성
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
            .setSubject(subject)
            .setIssuedAt(Calendar.getInstance().getTime())
            .setExpiration(expiration)
            .signWith(key)
            .compact();
    }
    //ㄴ> Access Token을 새로 발급
    //ㄴ> 별도의 Custom Claims는 추가할 필요 X


    private Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey) { //jwt signature에 사용할 비밀 키 생성
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey); //ase64 형식으로 인코딩 된 Secret Key를 디코딩 > byteArray 반환
        Key key = Keys.hmacShaKeyFor(keyBytes); //java.security.Key 객체 생성

        return key;
    }

    public void verifySignature(String jws, String base64EncodedSecretKey) { //JWT 검증 메소드
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        Jwts.parserBuilder()
            .setSigningKey(key)     // 서명에 사용된 Secret Key를 설정
            .build()
            .parseClaimsJws(jws);   // JWT를 파싱 > Claims 얻기
    }

    //* Plain Text 자체를 Secret Key로 사용 하는 건 X
    //* jjwt 최신 버전(0.11.5)에서는 서명 과정에서 내부적으로 적절한 HMAC 알고리즘을 지정 (직접지정 X)
}
