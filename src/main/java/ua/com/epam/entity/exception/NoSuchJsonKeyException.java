package ua.com.epam.entity.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class NoSuchJsonKeyException extends RuntimeException {
    private String propName;
}
