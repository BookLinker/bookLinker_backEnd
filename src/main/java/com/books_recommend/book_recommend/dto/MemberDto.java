package com.books_recommend.book_recommend.dto;

import com.books_recommend.book_recommend.entity.Member;

import java.util.List;

public record MemberDto (
    Long id,
    String nickName,
    List<String> roles
    ){
    public static MemberDto fromEntity(Member member){
        return new MemberDto(
                member.getId(),
                member.getNickName(),
                member.getRoles()
        );
    }
}
