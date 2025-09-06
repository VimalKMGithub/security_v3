package org.vimal.security.v3.exceptions;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MissingRequestValueException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.*;

import static org.vimal.security.v3.utils.JsonUtility.toJson;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, String>> handleAuthenticationException(AuthenticationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of(
                                "error", "Unauthorized",
                                "message", ex.getMessage()
                        )
                );
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleAccessDeniedException(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of(
                                "error", "Forbidden",
                                "message", ex.getMessage()
                        )
                );
    }

    @ExceptionHandler(ServiceUnavailableException.class)
    public ResponseEntity<Map<String, String>> handleServiceUnavailableException(ServiceUnavailableException ex) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of(
                                "message", "Service Unavailable",
                                "reason", ex.getMessage()
                        )
                );
    }

    @ExceptionHandler({
            SimpleBadRequestException.class,
            HttpMessageNotReadableException.class,
            NoResourceFoundException.class,
            MissingRequestValueException.class
    })
    public ResponseEntity<Map<String, String>> handleBadRequestExceptions(Exception ex) {
        return ResponseEntity.badRequest()
                .body(Map.of(
                                "error", "Bad Request",
                                "message", ex.getMessage()
                        )
                );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) throws JsonProcessingException {
        HashMap<String, Object> errorResponse = new LinkedHashMap<>();
        errorResponse.put("severity", "Error");
        errorResponse.put("message", ex.getMessage());
        HashMap<String, Object> innerErrorData = new LinkedHashMap<>();
        innerErrorData.put("exception", ex.toString());
        innerErrorData.put("stack", formatStackTrace(ex));
        errorResponse.put("innerErrorData", innerErrorData);
        log.error("An unexpected error occurred: {}\n{}", ex.getMessage(), toJson(errorResponse));
        return ResponseEntity.internalServerError().body(errorResponse);
    }

    private List<String> formatStackTrace(Throwable ex) {
        StackTraceElement[] stackTrace = ex.getStackTrace();
        List<String> stackTraceFormatted = new ArrayList<>(stackTrace.length);
        for (StackTraceElement ste : stackTrace) {
            stackTraceFormatted.add(ste.getClassName() + "." +
                    ste.getMethodName() + "(" +
                    ste.getFileName() + ":" +
                    ste.getLineNumber() + ")");
        }
        return stackTraceFormatted;
    }
}
