package com.books_recommend.book_recommend.common.auth.filter;

import com.books_recommend.book_recommend.common.auth.JwtTokenizer;
import com.books_recommend.book_recommend.dto.MemberDto;
import com.books_recommend.book_recommend.entity.Member;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.*;

//loginFilter
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    //UsernamePasswordAuthenticationFilter는 폼 로그인 디폴트 Security Filter
    //ㄴ> UsernamePasswordAuthenticationFilter를 확장해서 구현 가능 (로그인 처리)

    private final AuthenticationManager authenticationManager; //인증 여부 판단
    private final JwtTokenizer jwtTokenizer; //인증 성공시 토큰 발급


    // (3)
    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        var objectMapper = new ObjectMapper();    //DTO 클래스로 역직렬화를 위해 ObjectMapper 생성
        var memberDto = objectMapper.readValue(request.getInputStream(), MemberDto.class); //역직렬화

        //UsernamePasswordAuthenticationToken 생성 (email, pw 포함)
        var authenticationToken =
            new UsernamePasswordAuthenticationToken(memberDto.email(), memberDto.password());

        return authenticationManager.authenticate(authenticationToken);  //토큰 전달 (AuthenticationManager한테) 및 인증 처리 위임
    }

    //인증에 성공할 경우 호출
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) {
        var member = (Member) authResult.getPrincipal();  //Member 엔티티 클래스의 객체 얻기

        var accessToken = delegateAccessToken(member);   //AccessToken 생성
        var refreshToken = delegateRefreshToken(member); //RefreshToken 생성

        response.setHeader("Authorization", "Bearer " + accessToken);  //responseHeaderdp xhzms cnrk
        response.setHeader("Refresh", refreshToken);  //refresh도 마찬가지
    }

    //accessToken 생성하는 구체적 로직
    private String delegateAccessToken(Member member) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", member.getEmail());
        claims.put("roles", member.getRoles());

        var subject = member.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getAccessTokenExpirationMinutes());

        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);

        return accessToken;
    }

    //refreshToken 생성하는 구체적 로직
    private String delegateRefreshToken(Member member) {
        String subject = member.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getRefreshTokenExpirationMinutes());
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String refreshToken = jwtTokenizer.generateRefreshToken(subject, expiration, base64EncodedSecretKey);

        return refreshToken;
    }
}
