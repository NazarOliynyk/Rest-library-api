package ua.com.epam.controller;

import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ua.com.epam.entity.dto.book.BookDto;
import ua.com.epam.exception.entity.NoSuchJsonKeyException;
import ua.com.epam.exception.entity.type.InvalidOrderTypeException;
import ua.com.epam.exception.entity.type.InvalidPageValueException;
import ua.com.epam.exception.entity.type.InvalidSizeValueException;
import ua.com.epam.repository.JsonKeysConformity;
import ua.com.epam.service.BookService;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("${server.base.url}")
@Api(value = "Book", description = "Book endpoints", tags = {"Book"})
public class BookController {

    @Autowired
    private BookService bookService;

    private void checkOrdering(String orderType) {
        if (!orderType.equals("asc") && !orderType.equals("desc")) {
            throw new InvalidOrderTypeException(orderType);
        }
    }

    private void checkSortByKeyInGroup(String sortBy) {
        if (!JsonKeysConformity.ifJsonKeyExistsInGroup(sortBy, JsonKeysConformity.Group.BOOK)
                && !sortBy.equalsIgnoreCase("volume")
                && !sortBy.equalsIgnoreCase("square")) {
            throw new NoSuchJsonKeyException(sortBy);
        }
    }

    private void checkPaginateParams(int page, int size) {
        if (page <= 0) {
            throw new InvalidPageValueException();
        }
        if (size <= 0) {
            throw new InvalidSizeValueException();
        }
    }

    @ApiOperation(value = "get Book object by 'bookId'", tags = {"Book"})
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Special Book object in JSON", response = BookDto.class),
            @ApiResponse(code = 400, message = "Something wrong..."),
            @ApiResponse(code = 404, message = "Book not found")
    })
    @GetMapping(value = "/book/{bookId}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getBook(
            @ApiParam(required = true, value = "existed Book ID")
            @PathVariable
                    Long bookId) {
        BookDto response = bookService.findBook(bookId);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @ApiOperation(value = "get all Books", tags = {"Book"})
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Array of Book objects",
                    responseContainer = "Set", response = BookDto.class),
            @ApiResponse(code = 400, message = "Something wrong...")
    })
    @GetMapping(value = "/books",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getAllBooks(
            @ApiParam(value = "paginate response")
            @RequestParam(name = "pagination", defaultValue = "true")
                    Boolean pagination,

            @ApiParam(value = "page number")
            @RequestParam(name = "page", defaultValue = "1")
                    Integer page,

            @ApiParam(value = "count of objects per one page")
            @RequestParam(name = "size", defaultValue = "1000")
                    Integer size,

            @ApiParam(value = "custom sort parameter\ncan also assume 'square' and 'volume' parameters")
            @RequestParam(name = "sortBy", defaultValue = "bookId")
                    String sortBy,

            @ApiParam(allowableValues = "asc,desc", value = "sorting order")
            @RequestParam(name = "orderType", defaultValue = "asc")
                    String orderType) {
        checkSortByKeyInGroup(sortBy);
        checkOrdering(orderType);
        checkPaginateParams(page, size);

        List<BookDto> response = bookService.findAllBooks(sortBy, orderType, page, size, pagination);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @ApiOperation(value = "get all Books of special Genre", tags = {"Book"})
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Array of Book objects",
                    responseContainer = "Set", response = BookDto.class),
            @ApiResponse(code = 400, message = "Something wrong...")
    })
    @GetMapping(value = "/genre/{genreId}/books",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getAllBooksInGenre(
            @ApiParam(required = true, value = "existed Genre ID")
            @PathVariable
                    Long genreId,

            @ApiParam(value = "paginate response")
            @RequestParam(name = "pagination", defaultValue = "true")
                    Boolean pagination,

            @ApiParam(value = "page number")
            @RequestParam(name = "page", defaultValue = "1")
                    Integer page,

            @ApiParam(value = "count of objects per one page")
            @RequestParam(name = "size", defaultValue = "10")
                    Integer size,

            @ApiParam(value = "custom sort parameter")
            @RequestParam(name = "sortBy", defaultValue = "bookId")
                    String sortBy,

            @ApiParam(allowableValues = "asc,desc", value = "sorting order")
            @RequestParam(name = "orderType", defaultValue = "asc")
                    String orderType) {
        checkSortByKeyInGroup(sortBy);
        checkOrdering(orderType);
        checkPaginateParams(page, size);

        List<BookDto> response = bookService.findBooksInGenre(genreId, sortBy, orderType, page, size, pagination);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @ApiOperation(value = "get all Books of special Author", tags = {"Book"})
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Array of Book objects",
                    responseContainer = "Set", response = BookDto.class),
            @ApiResponse(code = 400, message = "Something wrong...")
    })
    @GetMapping(value = "/author/{authorId}/books",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getAllAuthorBooks(
            @ApiParam(required = true, value = "existed Author ID")
            @PathVariable
                    Long authorId,

            @ApiParam(value = "custom sort parameter")
            @RequestParam(name = "sortBy", defaultValue = "bookId")
                    String sortBy,

            @ApiParam(allowableValues = "asc,desc", value = "sorting order")
            @RequestParam(name = "orderType", defaultValue = "asc")
                    String orderType) {
        checkSortByKeyInGroup(sortBy);
        checkOrdering(orderType);

        List<BookDto> response = bookService.findAuthorBooks(authorId, sortBy, orderType);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @ApiOperation(value = "get all Books of special Author in special Genre", tags = {"Book"})
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Array of Book objects",
                    responseContainer = "Set", response = BookDto.class),
            @ApiResponse(code = 400, message = "Something wrong..."),
            @ApiResponse(code = 404, message = "Author or Genre not found")
    })
    @GetMapping(value = "/author/{authorId}/genre/{genreId}/books",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getAllAuthorBooksInGenre(
            @ApiParam(required = true, value = "existed Author ID")
            @PathVariable
                    Long authorId,

            @ApiParam(required = true, value = "existed Genre ID")
            @PathVariable
                    Long genreId) {
        List<BookDto> response = bookService.findBooksOfAuthorInGenre(authorId, genreId);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @ApiOperation(value = "search for books by book name, return first 5 the most relevant results", tags = {"Book"})
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Array of Book objects",
                    responseContainer = "Set", response = BookDto.class),
            @ApiResponse(code = 400, message = "Something wrong...")
    })
    @GetMapping(value = "/books/search",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> searchForExistedBooks(
            @ApiParam(value = "Searched query. At least 5 symbols exclude spaces in each word.", required = true)
            @RequestParam(name = "q")
                    String query) {
        List<BookDto> response = bookService.searchForExistedBooks(query);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @ApiOperation(value = "create new Book", tags = {"Book"})
    @ApiResponses(value = {
            @ApiResponse(code = 201, message = "newly created Book", response = BookDto.class),
            @ApiResponse(code = 400, message = "Something wrong..."),
            @ApiResponse(code = 409, message = "Book with such id already exists")
    })
    @ResponseStatus(value = HttpStatus.CREATED)
    @PostMapping(value = "/book/{authorId}/{genreId}",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> addNewBook(
            @ApiParam(required = true, value = "existed Author ID")
            @PathVariable
                    Long authorId,

            @ApiParam(required = true, value = "existed Genre ID")
            @PathVariable
                    Long genreId,

            @ApiParam(required = true, value = "Book to add", name = "Book object")
            @RequestBody @Valid
                    BookDto newBook) {
        BookDto response = bookService.addNewBook(authorId, genreId, newBook);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @ApiOperation(value = "update existed Book", tags = {"Book"})
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "updated Book object", response = BookDto.class),
            @ApiResponse(code = 400, message = "Something wrong..."),
            @ApiResponse(code = 404, message = "Book to update not found")
    })
    @PutMapping(value = "/book/{bookId}",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> updateBook(
            @ApiParam(required = true, value = "existed Book ID")
            @PathVariable
                    Long bookId,

            @ApiParam(required = true, value = "Book to update", name = "Book object")
            @RequestBody @Valid
                    BookDto updatedBook) {
        BookDto response = bookService.updateExistedBook(bookId, updatedBook);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @ApiOperation(value = "delete existed Book", tags = {"Book"})
    @ApiResponses(value = {
            @ApiResponse(code = 204, message = "Book deleted successfully"),
            @ApiResponse(code = 400, message = "Something wrong..."),
            @ApiResponse(code = 404, message = "Book to delete not found")
    })
    @ResponseStatus(value = HttpStatus.NO_CONTENT)
    @DeleteMapping(value = "/book/{bookId}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> deleteBook(
            @ApiParam(required = true, value = "existed Book ID")
            @PathVariable
                    Long bookId) {
        bookService.deleteExistedBook(bookId);
        return new ResponseEntity<>("", HttpStatus.NO_CONTENT);
    }
}