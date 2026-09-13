package cl.andesstay.bff.web;

import java.time.LocalDate;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint de reservas con datos de ejemplo.
 *
 * <p>Existe para poder probar las rutas del API Gateway antes de que el dominio este
 * construido: alcanza para demostrar que una ruta valida el JWT, llama al backend y devuelve el
 * JSON esperado, que es lo que pide el indicador 8 de la EP2.
 *
 * <p>Cuando ms-andesstay-reservations este listo, este controlador pasa a delegar en el
 * microservicio de dominio con un RestClient, propagando el Bearer. El contrato que debe
 * respetar esta en docs/contracts/openapi/reservations.yaml.
 */
@RestController
@RequestMapping("/api/reservations")
public class ReservationsController {

    /**
     * Lista reservas.
     *
     * <p>Cualquiera de los cuatro roles autenticados puede llegar aca. El filtrado por
     * propiedad (un huesped solo ve las propias) se resuelve comparando el {@code sub} del
     * token, y se implementa cuando exista el dominio.
     */
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'RECEPCIONISTA', 'HUESPED')")
    public List<ReservaResumen> listar(@AuthenticationPrincipal Jwt jwt) {
        return List.of(
                new ReservaResumen(
                        "R-2026-000123", "U-045", jwt.getSubject(),
                        LocalDate.of(2026, 10, 12), LocalDate.of(2026, 10, 15),
                        2, "CONFIRMADA"),
                new ReservaResumen(
                        "R-2026-000124", "U-012", jwt.getSubject(),
                        LocalDate.of(2026, 11, 3), LocalDate.of(2026, 11, 5),
                        4, "CREADA"));
    }

    /**
     * Devuelve los claims relevantes del token.
     *
     * <p>Sirve para demostrar en la presentacion que los roles y scopes se leen del token y no
     * estan escritos en el codigo, que es parte del 100% del indicador 1 de la EP1.
     */
    @GetMapping("/whoami")
    public Identidad whoami(@AuthenticationPrincipal Jwt jwt) {
        return new Identidad(
                jwt.getSubject(),
                jwt.getClaimAsString("name"),
                jwt.getIssuer().toString(),
                jwt.getAudience(),
                jwt.getClaimAsStringList("roles"),
                jwt.getClaimAsString("scp"),
                jwt.getExpiresAt());
    }

    public record ReservaResumen(
            String id, String unitId, String guestId,
            LocalDate fechaEntrada, LocalDate fechaSalida,
            int huespedes, String estado) {
    }

    public record Identidad(
            String sub, String nombre, String issuer, List<String> audience,
            List<String> roles, String scope, java.time.Instant expira) {
    }
}
