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

import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Verifica las reglas de seguridad del BFF sin contactar Azure AD:
 *  - 401 sin token o con token inválido
 *  - 403 con token válido pero sin el rol requerido
 *  - 200 con el rol correcto
 */
/*
 * Los servicios de aguas abajo apuntan a un puerto cerrado A PROPOSITO.
 *
 * Lo que esta clase comprueba son las decisiones del BFF, y una peticion que pasa la autorizacion
 * la reenvia el gateway al servicio correspondiente. Con los valores por omision eso es
 * http://localhost:8081, asi que un ms-andesstay-reservations de desarrollo levantado en la
 * maquina --lo normal mientras se trabaja-- atenderia la peticion, validaria el JWT por su cuenta
 * y rechazaria el token simulado con un 401. El resultado dependeria de que haya levantado quien
 * ejecuta las pruebas, que es la peor clase de prueba inestable: la que pasa en integracion
 * continua y falla en local, o al reves.
 *
 * Con el puerto 9 el reenvio falla siempre igual, y lo que queda medido es solo el BFF.
 */
@SpringBootTest(properties = {
        "RESERVATIONS_URL=http://127.0.0.1:9",
        "CATALOG_URL=http://127.0.0.1:9",
        "REPORT_URL=http://127.0.0.1:9",
        "AUDIT_URL=http://127.0.0.1:9",
})
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
        client.get().uri("/api/v1/reservations")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody().jsonPath("$.status").isEqualTo(401);
    }

    @Test
    void tokenMalformado_devuelve401InvalidToken() {
        client.get().uri("/api/v1/report/kpis")
                .header(HttpHeaders.AUTHORIZATION, "Bearer esto-no-es-un-jwt")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
    }

    @Test
    void clienteEnReporteria_devuelve403() {
        client.mutateWith(jwtWithRoles("Cliente"))
                .get().uri("/api/v1/report/kpis")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.status").isEqualTo(403);
    }

    /**
     * El BFF NO bloquea al huesped en esta ruta, y es deliberado.
     *
     * Antes esperaba un 403, y era correcto cuando la ruta estaba reservada a Operador y Admin. Al
     * dejar al huesped cancelar su propia reserva hubo que abrirsela, porque el BFF no puede
     * decidir: no sabe de quien es la reserva ni en que estado esta. La regla de que solo puede
     * cancelar SU reserva y solo mientras siga en CREADA la aplica ms-andesstay-reservations, y
     * esta cubierta por los casos 8, 9 y 9 bis de su MaquinaDeEstadosTest.
     *
     * Lo que se afirma aqui es por tanto una ausencia: que el 403 no salga del BFF. El codigo
     * concreto que devuelva el reenvio no importa --el servicio de aguas abajo apunta a un puerto
     * cerrado, ver la anotacion de clase-- y afirmarlo ataria la prueba a un detalle que no es
     * suyo.
     */
    @Test
    void clienteCambiandoEstadoDeReserva_noLoBloqueaElBff() {
        client.mutateWith(jwtWithRoles("Cliente"))
                .put().uri("/api/v1/reservations/1/status")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"status\":\"CONFIRMADA\"}")
                .exchange()
                .expectStatus().value(codigo -> assertNotEquals(403, codigo,
                        "el BFF no debe bloquear al huesped: la regla de propiedad y de estado "
                                + "la aplica ms-andesstay-reservations"));
    }

    @Test
    void operadorCreandoUnidad_devuelve403() {
        client.mutateWith(jwtWithRoles("Operador"))
                .post().uri("/api/v1/catalog/units")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void auditorEscribiendoEnAuditoria_devuelve403() {
        client.mutateWith(jwtWithRoles("Auditor"))
                .post().uri("/api/v1/audit/events")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void adminEnMe_devuelve200ConRolesYScopes() {
        client.mutateWith(jwtWithRoles("Admin"))
                .get().uri("/api/v1/me")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.sub").isEqualTo("user-123")
                .jsonPath("$.roles[0]").isEqualTo("Admin")
                .jsonPath("$.scopes[0]").isEqualTo("AndesStay.Access")
                .jsonPath("$.authorities[?(@ == 'ROLE_Admin')]").exists()
                .jsonPath("$.authorities[?(@ == 'SCOPE_AndesStay.Access')]").exists();
    }

    private static JwtMutator jwtDeInvitadoAutoregistrado() {
        return SecurityMockServerConfigurers.mockJwt()
                .jwt(jwt -> jwt
                        .subject("huesped-456")
                        .claim("acct", 1L)
                        .claim("email", "huesped@gmail.com")
                        .claim("scp", "AndesStay.Access"))
                .authorities(SecurityConfig.authoritiesConverter());
    }

    @Test
    void invitadoAutoregistrado_enMe_recibeRolClienteEfectivo() {
        client.mutateWith(jwtDeInvitadoAutoregistrado())
                .get().uri("/api/v1/me")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.roles").isEmpty()
                .jsonPath("$.effectiveRoles[0]").isEqualTo("Cliente")
                .jsonPath("$.email").isEqualTo("huesped@gmail.com")
                .jsonPath("$.acct").isEqualTo(1)
                .jsonPath("$.authorities[?(@ == 'ROLE_Cliente')]").exists();
    }

    @Test
    void invitadoAutoregistrado_enReporteria_devuelve403() {
        client.mutateWith(jwtDeInvitadoAutoregistrado())
                .get().uri("/api/v1/report/kpis")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void tokenSinRolNiScope_enMe_devuelve403() {
        client.mutateWith(SecurityMockServerConfigurers.mockJwt()
                        .jwt(jwt -> jwt.subject("sin-permisos"))
                        .authorities(SecurityConfig.authoritiesConverter()))
                .get().uri("/api/v1/me")
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
