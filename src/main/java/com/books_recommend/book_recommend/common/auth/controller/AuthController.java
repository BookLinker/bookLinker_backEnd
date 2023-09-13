package com.books_recommend.book_recommend.common.auth.controller;

import com.books_recommend.book_recommend.common.auth.service.AuthService;
import com.books_recommend.book_recommend.common.web.ApiResponse;
import com.books_recommend.book_recommend.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
@RestController
@RequestMapping
@RequiredArgsConstructor
public class AuthController {
    private final AuthService service;

    @PostMapping("members/login")
    ApiResponse<Map<String, String>> login(@RequestBody LoginRequest loginRequest) {
        var requirement = new AuthService.LoginRequirement(
            loginRequest.email,
            loginRequest.password
        );
        var info = service.login(requirement);
        return ApiResponse.success(info);
    }
    record LoginRequest(
        String email,
        String password
    ){}
}
