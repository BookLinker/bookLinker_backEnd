package com.books_recommend.book_recommend.controller;

import com.books_recommend.book_recommend.common.web.ApiResponse;
import com.books_recommend.book_recommend.dto.BookDto;
import com.books_recommend.book_recommend.dto.BookListDto;
import com.books_recommend.book_recommend.service.BookListService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/booklists")
@RequiredArgsConstructor
public class BookListController {
    private final BookListService service;

    @PostMapping("/{memberId}")
    ApiResponse<CreateBookListResponse> createBookList(@RequestBody CreateRequest request
        ,@PathVariable Long memberId){

        var listDto = service.create(request.toRequirement(), memberId);

        var response = new CreateBookListResponse(listDto.bookListId());
        return ApiResponse.success(response);
    }

    record CreateRequest(
        List<Long> bookIds,
        String title,
        String backImg,
        String content
    ) {
        public BookListService.CreateRequirement toRequirement() {
            return new BookListService.CreateRequirement(
                bookIds,
                title,
                backImg,
                content
            );
        }
    }
    record CreateBookListResponse(
        Long id
    ) {}

    @GetMapping("/{listId}")
    ApiResponse<GetBookListResponse> getList(@PathVariable Long listId){
        var list = service.getList(listId);
        var response = GetBookListResponse.to(list);
        return ApiResponse.success(response);
    }

    record GetBookListResponse(
        Long listId,
        String title,
        String backImg,
        String content,
        List<BookDto> books
    ){
        static BookListController.GetBookListResponse to(BookListDto listDto){
            return new BookListController.GetBookListResponse(
                listDto.bookListId(),
                listDto.title(),
                listDto.backImg(),
                listDto.content(),
                listDto.books()
            );
        }
    }
}
