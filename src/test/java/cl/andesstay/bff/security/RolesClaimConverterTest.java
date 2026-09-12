package cl.andesstay.bff.security;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * El indicador 1 de la EP1 exige al 100% que "se leen roles y scopes desde los claims del
 * token". Estos casos verifican esa traduccion, incluido el comportamiento cuando el rol no
 * viene, que en la practica significa que se olvido asignarlo en Enterprise applications.
 */
class RolesClaimConverterTest {

    private final RolesClaimConverter converter = new RolesClaimConverter();

    @Test
    @DisplayName("traduce los app roles de Azure a authorities ROLE_")
    void traduceRoles() {
        AbstractAuthenticationToken token = converter.convert(
                tokenCon(List.of("Admin", "Recepcionista"), "access_as_staff"));

        assertThat(nombresDe(token)).contains("ROLE_ADMIN", "ROLE_RECEPCIONISTA");
    }

    @Test
    @DisplayName("normaliza a mayusculas, asi el nombre del rol en Azure no importa")
    void normalizaMayusculas() {
        AbstractAuthenticationToken token = converter.convert(
                tokenCon(List.of("huesped"), "access_as_guest"));

        assertThat(nombresDe(token)).contains("ROLE_HUESPED");
    }

    @Test
    @DisplayName("expone tambien el scope como SCOPE_")
    void exponeScope() {
        AbstractAuthenticationToken token = converter.convert(
                tokenCon(List.of("Auditor"), "access_as_staff"));

        assertThat(nombresDe(token)).contains("ROLE_AUDITOR", "SCOPE_access_as_staff");
    }

    @Test
    @DisplayName("un token sin claim roles autentica pero queda sin ningun ROLE_")
    void sinRolesNoAutoriza() {
        Jwt sinRoles = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .claim("sub", "usuario-sin-rol")
                .claim("scp", "access_as_staff")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();

        AbstractAuthenticationToken token = converter.convert(sinRoles);

        assertThat(token.isAuthenticated()).isTrue();
        assertThat(nombresDe(token)).noneMatch(nombre -> nombre.startsWith("ROLE_"));
    }

    @Test
    @DisplayName("el subject del token queda como nombre de la autenticacion")
    void usaSubjectComoNombre() {
        AbstractAuthenticationToken token = converter.convert(
                tokenCon(List.of("Huesped"), "access_as_guest"));

        assertThat(token.getName()).isEqualTo("usuario-01");
    }

    private List<String> nombresDe(AbstractAuthenticationToken token) {
        return token.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
    }

    private Jwt tokenCon(List<String> roles, String scope) {
        return Jwt.withTokenValue("token-de-prueba")
                .header("alg", "RS256")
                .claim("sub", "usuario-01")
                .claim("roles", roles)
                .claim("scp", scope)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }
}
