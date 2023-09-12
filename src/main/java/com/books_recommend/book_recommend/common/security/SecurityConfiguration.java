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
}