package cl.andesstay.bff.security;

import java.io.IOException;
import java.util.UUID;

import cl.andesstay.bff.web.ApiError;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Responde <strong>401</strong> en JSON cuando la autenticacion falla.
 *
 * <p>Cubre todos los casos en que no se puede confiar en la identidad: falta la cabecera
 * Authorization, el token viene de un emisor desconocido, la firma no valida, el token expiro o
 * la audience no corresponde.
 *
 * <p>La distincion con 403 es explicita y se evalua: 401 significa "no se quien eres", 403
 * significa "se quien eres y no puedes". Ver docs/contracts/roles.md.
 */
public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    public JsonAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {

        String traceId = traceIdDe(request);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        objectMapper.writeValue(
                response.getOutputStream(),
                ApiError.de("TOKEN_INVALIDO", "Credenciales ausentes o no validas", traceId));
    }

    static String traceIdDe(HttpServletRequest request) {
        String recibido = request.getHeader("X-Trace-Id");
        return (recibido == null || recibido.isBlank()) ? UUID.randomUUID().toString() : recibido;
    }
}
