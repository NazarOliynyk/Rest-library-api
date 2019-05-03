package ua.com.epam.entity.dto.book;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import ua.com.epam.entity.dto.author.SimpleAuthorDto;
import ua.com.epam.entity.dto.book.nested.AdditionalDto;
import ua.com.epam.entity.dto.genre.SimpleGenreDto;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(value = "BookFull")
public class BookWithAuthorAndGenreDto {
    private Long bookId;
    private String bookName;
    private String bookLanguage;
    private AdditionalDto additional;
    private Integer publicationYear;
    private SimpleAuthorDto author;
    private SimpleGenreDto genre;
}
