package com.books_recommend.book_recommend.common.auth.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class CustomAuthorityUtils {
    @Value("${mail.address.admin}") //application.yml에 정의되어 있는 프로퍼티의 값을 클래스 내에서 사용, 관리자 권한을 가질 수 있는 이메일 주소
    private String adminMailAddress;

    //관리자용 권한 목록을 List<GrantedAuthority> 객체로 미리 생성
    private final List<GrantedAuthority> ADMIN_ROLES = AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER");

    //일반 사용 권한 목록을 List<GrantedAuthority> 객체로 미리 생성
    private final List<GrantedAuthority> USER_ROLES = AuthorityUtils.createAuthorityList("ROLE_USER");
    private final List<String> ADMIN_ROLES_STRING = List.of("ADMIN", "USER");
    private final List<String> USER_ROLES_STRING = List.of("USER");

    // 메모리 상의 Role을 기반으로 권한 정보 생성.
    public List<GrantedAuthority> createAuthorities(String email) {
        //파라미터로 전달받은 이메일 주소가 application.yml 파일에서 가져온 관리자용 이메일 주소와 동일하다면 관리자용 권한인 List<GrantedAuthority> ADMIN_ROLES를 리턴
        if (email.equals(adminMailAddress)) {
            return ADMIN_ROLES;
        }
        return USER_ROLES;
    }

    // DB에 저장된 Role을 기반으로 권한 정보 생성
    public List<GrantedAuthority> createAuthorities(List<String> roles) {
        List<GrantedAuthority> authorities = roles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
            .collect(Collectors.toList());
        return authorities;
    }
    //ㄴ> SimpleGrantedAuthority 객체를 생성할 때 생성자 파라미터로 넘겨주는 값이 “ USER" 또는 “ADMIN"으로 넘겨주면 안 되고 “ROLE_USER" 또는 “ROLE_ADMIN" 형태로 넘겨주어야 한다는 것

    // DB 저장 용
    public List<String> createRoles(String email) {
        if (email.equals(adminMailAddress)) {
            return ADMIN_ROLES_STRING;
        }
        return USER_ROLES_STRING;
    }
}