package cl.andesstay.bff.web;

import java.time.Instant;

/**
 * Cuerpo de error uniforme de la API.
 *
 * <p>No revela detalles internos: ni stack traces, ni nombres de clase, ni el motivo exacto por
 * el que un token fue rechazado. Un atacante no deberia poder distinguir "firma invalida" de
 * "audience incorrecta" a partir de la respuesta.
 *
 * <p>El {@code traceId} permite correlacionar la respuesta con los logs y con los eventos de
 * auditoria. Ver docs/contracts/events/envelope.md en el repositorio infra.
 */
public record ApiError(String error, String mensaje, Instant timestamp, String traceId) {

    public static ApiError de(String error, String mensaje, String traceId) {
        return new ApiError(error, mensaje, Instant.now(), traceId);
    }
}
