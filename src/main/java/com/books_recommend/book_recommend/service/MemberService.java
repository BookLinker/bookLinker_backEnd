package com.books_recommend.book_recommend.service;

import com.books_recommend.book_recommend.common.auth.JwtTokenizer;
import com.books_recommend.book_recommend.common.auth.util.CustomAuthorityUtils;
import com.books_recommend.book_recommend.common.exception.BusinessLogicException;
import com.books_recommend.book_recommend.common.exception.ExceptionCode;
import com.books_recommend.book_recommend.dto.MemberDto;
import com.books_recommend.book_recommend.entity.Member;
import com.books_recommend.book_recommend.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final CustomAuthorityUtils authorityUtils;
    private final JwtTokenizer jwtTokenizer;


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

        var savedMember = memberRepository.save(member);

        return savedMember.getId();
    }

    public record Requirement(
            String email,
            String nickname,
            String password
    ){}

    public Map<String, String> login(LoginRequirement requirement){
        //1. 이메일 매치는 멤버 가져오면 끝냄
        var member = memberRepository.findByEmail(requirement.email)
            .orElseThrow(()-> new BusinessLogicException(ExceptionCode.MEMBER_NOT_FOUND));

        //2. 비밀번호 매치
        checkPassword(member, requirement.password, passwordEncoder);

        //2. 인증 성공시 accessToken 생성 및 반환
        var claims = new HashMap<String, Object>() {{
            put("memberId", member.getId());//필요한 클레임 정보
        }};

        var accessToken = createAccessToken(claims, member, jwtTokenizer);

        var refreshToken = createRefreshToken(member, jwtTokenizer);

        var response = new HashMap<String, String>() {{
            put("accessToken", accessToken);
            put("refreshToken", refreshToken);
        }};
        return response;
    }

    private static void checkPassword(Member member, String password, PasswordEncoder passwordEncoder) {
        if (! passwordEncoder.matches(password, member.getPassword())){ //db에서 가져온 멤버, 사용자 입력 pw
            throw new BusinessLogicException(ExceptionCode.MEMBER_PASSWORD_INCONSISTENCY);
        }
    }

    private static String createAccessToken(HashMap<String,Object> claims,
                                    Member member,
                                    JwtTokenizer jwtTokenizer){
        return jwtTokenizer.generateAccessToken(claims, member.getEmail(),
            jwtTokenizer.getTokenExpiration(jwtTokenizer.getAccessTokenExpirationMinutes()),
            jwtTokenizer.getSecretKey());
    }

    private static String createRefreshToken(Member member, //재발급은 claims 개인정보 필요없음
                                            JwtTokenizer jwtTokenizer){
        return jwtTokenizer.generateRefreshToken(member.getEmail(),
            jwtTokenizer.getTokenExpiration(jwtTokenizer.getRefreshTokenExpirationMinutes()),
            jwtTokenizer.getSecretKey());
    }

    public record LoginRequirement(
        String email,
        String password
    ){}


    public Member findByEmail(String email) {
        return memberRepository.findByEmail(email)
            .orElseThrow(()-> new BusinessLogicException(ExceptionCode.MEMBER_NOT_FOUND));
    }
}
