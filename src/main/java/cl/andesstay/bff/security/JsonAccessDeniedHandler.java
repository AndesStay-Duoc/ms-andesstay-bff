package cl.andesstay.bff.security;

import java.io.IOException;

import cl.andesstay.bff.web.ApiError;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Responde <strong>403</strong> en JSON cuando el token es valido pero el rol no alcanza.
 *
 * <p>Tambien es la respuesta cuando un huesped intenta operar sobre una reserva ajena: se
 * devuelve 403 y no 404 a proposito, para no revelar si el recurso existe.
 */
public class JsonAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    public JsonAccessDeniedHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {

        String traceId = JsonAuthenticationEntryPoint.traceIdDe(request);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(
                response.getOutputStream(),
                ApiError.de("ROL_INSUFICIENTE", "El rol no permite esta operacion", traceId));
    }
}
