package com.books_recommend.book_recommend.service;


import com.books_recommend.book_recommend.common.properties.KakaoProperties;
import com.books_recommend.book_recommend.dto.KakaoBookDto;
import com.books_recommend.book_recommend.entity.Book;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class KakaoApiService {

    private final KakaoProperties kakaoProperties;
    private final RestTemplate restTemplate;

    public List<KakaoBookDto> searchBooks(String query) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("Authorization", "KakaoAK " + kakaoProperties.getKey());
        HttpEntity<String> httpEntity = new HttpEntity<>(httpHeaders);

        URI targetUrl = UriComponentsBuilder
            .fromUriString(getKakaoUrl())
            .queryParam("query", query)
            .build()
            .encode(StandardCharsets.UTF_8)
            .toUri();

        ResponseEntity<Map> result = restTemplate.exchange(targetUrl, HttpMethod.GET, httpEntity, Map.class);

        List<Map<String, Object>> bookDataList = (List<Map<String, Object>>) result.getBody().get("documents");

        // KakaoBookDto로 변환하여 반환
        return mapToKakaoBookDtos(bookDataList);
    }

    private List<KakaoBookDto> mapToKakaoBookDtos(List<Map<String, Object>> bookDataList) {
        List<KakaoBookDto> bookDtos = new ArrayList<>();

        if (bookDataList != null) {
            for (Map<String, Object> bookData : bookDataList) {
                String title = (String) bookData.get("title");
                List<String> authors = (List<String>) bookData.get("authors");
                String isbn = (String) bookData.get("isbn");
                String publisher = (String) bookData.get("publisher");
                String image = (String) bookData.get("thumbnail");
                String url = (String) bookData.get("url");

                KakaoBookDto bookDto = new KakaoBookDto(title, authors, isbn, publisher, image, url);
                bookDtos.add(bookDto);
            }
        }

        return bookDtos;
    }

    private String getKakaoUrl() {
        return "https://dapi.kakao.com/v3/search/book";
    }
}