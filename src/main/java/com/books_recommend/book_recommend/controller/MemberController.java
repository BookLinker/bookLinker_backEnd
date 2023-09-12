package com.books_recommend.book_recommend.controller;

import com.books_recommend.book_recommend.common.web.ApiResponse;
import com.books_recommend.book_recommend.dto.MemberDto;
import com.books_recommend.book_recommend.service.MemberService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/members")
@RequiredArgsConstructor
@Valid
class MemberController {
    private final MemberService service;

    @PostMapping
    ApiResponse<Response> createMember(@Valid @RequestBody Request request){
        MemberDto memberDto = service.createMember(request.toRequirement());

        Response response =  new Response(memberDto.id());
        return ApiResponse.success(response);
    }

    record Request(
            @NotBlank(message = "email은 필수입니다.")
            @Pattern(regexp = "^[A-Za-z0-9_\\.\\-]+@[A-Za-z0-9\\-]+\\.[A-Za-z0-9\\-]+$",
            message = "올바른 이메일 형식이 아닙니다.")
            String email,
            @NotBlank(message = "nickname는 필수입니다.")
            String nickname,
            @NotBlank(message = "password는 필수입니다.")
            String password
    ) {
        public MemberService.Requirement toRequirement(){
            return new MemberService.Requirement(email,
                    nickname,
                    password);
        }
    }
    record Response(
            Long id
    ){}
}

