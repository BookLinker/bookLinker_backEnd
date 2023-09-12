package com.books_recommend.book_recommend.service;

import com.books_recommend.book_recommend.dto.MemberDto;
import com.books_recommend.book_recommend.entity.Member;
import com.books_recommend.book_recommend.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository repository;
    private final PasswordEncoder passwordEncoder;

    public MemberDto createMember(Requirement requirement){
//TODO 토큰 적용 이후        var encodedPassword = passwordEncoder.encode(requirement.password);
        var member = new Member(
            requirement.email,
            requirement.nickname,
            requirement.password
        );

        var saveMember = repository.save(member);

        return MemberDto.fromEntity(saveMember);
    }

    public record Requirement(
            String email,
            String nickname,
            String password
    ){}
}
