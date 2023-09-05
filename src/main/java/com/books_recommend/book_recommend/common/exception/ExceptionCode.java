package com.books_recommend.book_recommend.common.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

    @Getter
    @AllArgsConstructor
    public enum ExceptionCode {
        //List
        LIST_NOT_FOUND("존재하지 않는 리스트 입니다."),
        MEMBER_NOT_DELETE_LIST("리스트를 삭제할 수 없는 사용자 입니다."),
        MEMBER_NOT_FOUND("존재하지 않는 사용자 입니다"),
        BOOK_NOT_FOUND("존재하지 않는 책입니다.");


        private String message;
    }

