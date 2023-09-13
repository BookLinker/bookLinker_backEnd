package com.books_recommend.book_recommend.common.auth.config;

import com.books_recommend.book_recommend.common.auth.JwtTokenizer;
import com.books_recommend.book_recommend.common.auth.filter.JwtAuthenticationFilter;
import jakarta.servlet.DispatcherType;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;

//    @Bean //ver1 기본적인 것만 / 에러처리 못함
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//            .csrf((csrf) -> csrf
//                .ignoringRequestMatchers(new AntPathRequestMatcher("/members/**"))) //회원가입시 막히는 거
//
//            .headers((headers) -> headers
//                .addHeaderWriter(new XFrameOptionsHeaderWriter(
//                    XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN)))
//
//            .authorizeHttpRequests(
//                authorize -> authorize
//                    //member
//                    .requestMatchers("/members/**").permitAll() //.permitAll() 모든 허용
//                    .requestMatchers("/members/login").permitAll()
//
//                    //booksGet
//                    .requestMatchers("/booklists").permitAll()
//                    .requestMatchers("/booklists/search/**").permitAll()
//                    .requestMatchers("/books/**").permitAll()
//
//            );
//
//        return http.build();
//    }

    @Bean //ver2 로그인 토큰 인증 추가
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http

            .apply(new CustomFilterConfigurer())
            .and() // CustomFilterConfigurer 설정과 분리

            .csrf((csrf) -> csrf
                .ignoringRequestMatchers(new AntPathRequestMatcher("/members/**"))) // 회원가입시 막히는 거
            .csrf((csrf) -> csrf
                .ignoringRequestMatchers(new AntPathRequestMatcher("/members/login")))

            .headers((headers) -> headers
                .addHeaderWriter(new XFrameOptionsHeaderWriter(
                    XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN)))



            .authorizeHttpRequests(
                authorize -> authorize
                    // member
                    .requestMatchers("/members/**").permitAll() //.permitAll() 모든 허용
                    .requestMatchers( "/members/login").permitAll() // POST 요청에 대해 허용

                    // booksGet
                    .requestMatchers("/booklists").permitAll()
                    .requestMatchers("/booklists/search/**").permitAll()
                    .requestMatchers("/books/**").permitAll()

            );




        return http.build();
    }

    //CustomFilterConfigurer: Configuration 원하는 대로 시큐리티 설정할 수 있는 거
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity> {//AbstractHttpConfigurer를 상속해야 CustomFilter~ 구현가능
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            var authenticationManager = builder.getSharedObject(AuthenticationManager.class);  //AuthenticationManager 객체얻기

            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);  //AuthenticationManager, JwtTokenizer 의존성 주입
            jwtAuthenticationFilter.setFilterProcessesUrl("/members/login"); //requestURl 변경

            builder.addFilter(jwtAuthenticationFilter); //addFilter(): JwtAuthenticationFilter를 Spring Security Filter Chain 에 추가
        }
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