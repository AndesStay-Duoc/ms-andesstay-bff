package cl.andesstay.bff.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.JwtMutator;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.List;

/**
 * Verifica las reglas de seguridad del BFF sin contactar Azure AD:
 *  - 401 sin token o con token inválido
 *  - 403 con token válido pero sin el rol requerido
 *  - 200 con el rol correcto
 */
@SpringBootTest
@AutoConfigureWebTestClient
class SecurityConfigTest {

    @Autowired
    private WebTestClient client;

    private static JwtMutator jwtWithRoles(String... roles) {
        return SecurityMockServerConfigurers.mockJwt()
                .jwt(jwt -> jwt
                        .subject("user-123")
                        .claim("name", "Usuario Test")
                        .claim("roles", List.of(roles))
                        .claim("scp", "AndesStay.Access"))
                .authorities(SecurityConfig.authoritiesConverter());
    }

    @Test
    void sinToken_devuelve401ConWwwAuthenticate() {
        client.get().uri("/api/reservations")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody().jsonPath("$.status").isEqualTo(401);
    }

    @Test
    void tokenMalformado_devuelve401InvalidToken() {
        client.get().uri("/api/report/kpis")
                .header(HttpHeaders.AUTHORIZATION, "Bearer esto-no-es-un-jwt")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
    }

    @Test
    void clienteEnReporteria_devuelve403() {
        client.mutateWith(jwtWithRoles("Cliente"))
                .get().uri("/api/report/kpis")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.status").isEqualTo(403);
    }

    @Test
    void clienteCambiandoEstadoDeReserva_devuelve403() {
        client.mutateWith(jwtWithRoles("Cliente"))
                .put().uri("/api/reservations/1/status")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"status\":\"CONFIRMADA\"}")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void operadorCreandoUnidad_devuelve403() {
        client.mutateWith(jwtWithRoles("Operador"))
                .post().uri("/api/catalog/units")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void auditorEscribiendoEnAuditoria_devuelve403() {
        client.mutateWith(jwtWithRoles("Auditor"))
                .post().uri("/api/audit/events")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void adminEnMe_devuelve200ConRolesYScopes() {
        client.mutateWith(jwtWithRoles("Admin"))
                .get().uri("/api/me")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.sub").isEqualTo("user-123")
                .jsonPath("$.roles[0]").isEqualTo("Admin")
                .jsonPath("$.scopes[0]").isEqualTo("AndesStay.Access")
                .jsonPath("$.authorities[?(@ == 'ROLE_Admin')]").exists()
                .jsonPath("$.authorities[?(@ == 'SCOPE_AndesStay.Access')]").exists();
    }

    @Test
    void tokenSinRolNiScope_enMe_devuelve403() {
        client.mutateWith(SecurityMockServerConfigurers.mockJwt()
                        .jwt(jwt -> jwt.subject("sin-permisos"))
                        .authorities(SecurityConfig.authoritiesConverter()))
                .get().uri("/api/me")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void healthEsPublico() {
        client.get().uri("/actuator/health")
                .exchange()
                .expectStatus().isOk();
    }
}
