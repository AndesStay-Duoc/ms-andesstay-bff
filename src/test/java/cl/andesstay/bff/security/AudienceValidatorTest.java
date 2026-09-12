package cl.andesstay.bff.security;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * El audience es la validacion que Spring no hace por defecto y que la EP1 pide explicitamente
 * en su indicador 2. Estos casos cubren el que se rompe en la practica: un token legitimo,
 * firmado por el tenant correcto, pero emitido para otra aplicacion.
 */
class AudienceValidatorTest {

    private static final String AUDIENCE_PROPIA = "api://andesstay-staff-client-id";
    private static final String AUDIENCE_DE_HUESPEDES = "api://andesstay-guest-client-id";
    private static final String AUDIENCE_DE_GRAPH = "00000003-0000-0000-c000-000000000000";

    private final AudienceValidator validator = new AudienceValidator(AUDIENCE_PROPIA);

    @Test
    @DisplayName("acepta un token dirigido a esta API")
    void aceptaAudienceCorrecta() {
        OAuth2TokenValidatorResult resultado = validator.validate(tokenCon(List.of(AUDIENCE_PROPIA)));
        assertThat(resultado.hasErrors()).isFalse();
    }

    @Test
    @DisplayName("acepta un token con varias audiences si una es la propia")
    void aceptaEntreVariasAudiences() {
        Jwt token = tokenCon(List.of(AUDIENCE_DE_GRAPH, AUDIENCE_PROPIA));
        assertThat(validator.validate(token).hasErrors()).isFalse();
    }

    @Test
    @DisplayName("rechaza un token emitido para Microsoft Graph: es el error mas comun")
    void rechazaAudienceDeGraph() {
        OAuth2TokenValidatorResult resultado = validator.validate(tokenCon(List.of(AUDIENCE_DE_GRAPH)));

        assertThat(resultado.hasErrors()).isTrue();
        assertThat(resultado.getErrors())
                .first()
                .satisfies(error -> assertThat(error.getErrorCode()).isEqualTo("invalid_token"));
    }

    @Test
    @DisplayName("rechaza un token sin audience")
    void rechazaSinAudience() {
        assertThat(validator.validate(tokenCon(List.of())).hasErrors()).isTrue();
    }

    @Test
    @DisplayName("no se puede construir sin audience esperada: seria un validador inutil")
    void exigeAudienceEsperada() {
        assertThatThrownBy(() -> new AudienceValidator("  "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("tampoco con una lista vacia o solo de blancos")
    void exigeAudienceEnLaLista() {
        assertThatThrownBy(() -> new AudienceValidator(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AudienceValidator(List.of(" ", "")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("con dos audiences acepta cualquiera de las dos: personal y huespedes en un mismo tenant")
    void aceptaVariasAudiencesConfiguradas() {
        AudienceValidator dosApps = new AudienceValidator(
                List.of(AUDIENCE_PROPIA, AUDIENCE_DE_HUESPEDES));

        assertThat(dosApps.validate(tokenCon(List.of(AUDIENCE_PROPIA))).hasErrors()).isFalse();
        assertThat(dosApps.validate(tokenCon(List.of(AUDIENCE_DE_HUESPEDES))).hasErrors()).isFalse();
    }

    @Test
    @DisplayName("con dos audiences sigue rechazando una tercera")
    void rechazaAudienceAjenaAunConVarias() {
        AudienceValidator dosApps = new AudienceValidator(
                List.of(AUDIENCE_PROPIA, AUDIENCE_DE_HUESPEDES));

        assertThat(dosApps.validate(tokenCon(List.of(AUDIENCE_DE_GRAPH))).hasErrors()).isTrue();
    }

    private Jwt tokenCon(List<String> audience) {
        return Jwt.withTokenValue("token-de-prueba")
                .header("alg", "RS256")
                .claim("aud", audience)
                .claim("sub", "usuario-01")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claims(c -> c.putIfAbsent("iss", "https://login.microsoftonline.com/tenant/v2.0"))
                .build();
    }
}
