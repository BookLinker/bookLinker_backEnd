package com.books_recommend.book_recommend.service;

import com.books_recommend.book_recommend.common.auth.util.CustomAuthorityUtils;
import com.books_recommend.book_recommend.dto.MemberDto;
import com.books_recommend.book_recommend.entity.Member;
import com.books_recommend.book_recommend.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final CustomAuthorityUtils authorityUtils;

    public Long createMember(Requirement requirement){
        var encodedPassword = passwordEncoder.encode(requirement.password);

        //사용자의 권한 정보를 생성
        var roles = authorityUtils.createRoles(requirement.email);

        var member = new Member(
            requirement.email,
            requirement.nickname,
            encodedPassword,
            roles
        );

        var savedMember = repository.save(member);

        return savedMember.getId();
    }

    public record Requirement(
            String email,
            String nickname,
            String password
    ){}
}
