package com.books_recommend.book_recommend.common.auth;

import org.springframework.security.access.AccessDeniedException;
import com.books_recommend.book_recommend.common.web.ApiResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // ApiResponse를 사용하여 에러 응답 생성
        ApiResponse<Void> errorResponse = ApiResponse.error("접근 거부: " + accessDeniedException.getMessage());

        // HTTP 상태 코드를 403 Forbidden으로 설정
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        // 응답을 JSON 형식으로 작성
        response.setContentType("application/json");
        response.getWriter().write(errorResponse.toString()); //ApiResponse 객체 문자열로 변환하여 작성
    }
}