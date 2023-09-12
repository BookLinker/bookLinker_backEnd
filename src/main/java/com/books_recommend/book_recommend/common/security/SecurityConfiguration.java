package com.books_recommend.book_recommend.common.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity //모든 요청 url이 springSecurity의 요청을 받도록
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf((csrf) -> csrf
                .ignoringRequestMatchers(new AntPathRequestMatcher("/members/**"))) //회원가입시 막히는 거

            .headers((headers) -> headers
                .addHeaderWriter(new XFrameOptionsHeaderWriter(
                    XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN)))

            .authorizeHttpRequests(
                authorize -> authorize
                    //member
                    .requestMatchers("/members/**").permitAll() //.permitAll() 모든 허용
                    .requestMatchers("/members/login").permitAll()

                    //booksGet
                    .requestMatchers("/booklists").permitAll()
                    .requestMatchers("/booklists/search/**").permitAll()
                    .requestMatchers("/books/**").permitAll()

            );

        return http.build();
    }

    @Bean //패스워드 암호화 기능을 제공하는 컴포넌트
    public PasswordEncoder passwordEncoder() { //얘 없으면 서비스에서 안돎
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        //ㄴ> 여기서 실질적인 PasswordEncoder 구현 객체 생성
    }

    @Bean// CorsConfigurationSource Bean 생성 > 구체적인 Cors 설정
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));   //모든 출처(Origin)에 대해 스크립트 기반의 HTTP 통신을 허용
        configuration.setAllowedMethods(Arrays.asList("GET","POST", "PATCH", "DELETE"));  //파라미터로 지정한 HTTP Method에 대한 HTTP 통신을 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();   //CorsConfigurationSource 구현 클래스 생성
        source.registerCorsConfiguration("/**", configuration); //모든 URL에 앞에서 구성한 CORS 정책 적용
        return source;
    }
}