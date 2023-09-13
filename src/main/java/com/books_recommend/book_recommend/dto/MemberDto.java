package com.books_recommend.book_recommend.dto;

import com.books_recommend.book_recommend.entity.Member;

import java.util.List;

public record MemberDto (
    Long id,
    String email,
    String nickName,
    String password,
    List<String> roles
    ){}
