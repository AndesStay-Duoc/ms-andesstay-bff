package cl.andesstay.bff.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifica los validadores del JWT: issuer, audience (ambos formatos) y vigencia.
 * La firma la valida NimbusReactiveJwtDecoder contra las claves JWKS de Azure AD.
 */
class JwtValidatorTest {

    private static final String TENANT_ID = "055d11d1-8ae0-4221-a6f7-b50be0a623b4";
    private static final String CLIENT_ID = "704a544f-3d92-44f5-aef9-8559574cff34";
    private static final String ISSUER = "https://login.microsoftonline.com/" + TENANT_ID + "/v2.0";

    private final OAuth2TokenValidator<Jwt> validator =
            SecurityConfig.jwtValidator(ISSUER, List.of("api://" + CLIENT_ID, CLIENT_ID));

    private static Jwt token(String issuer, String audience, Instant expiresAt) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .issuer(issuer)
                .audience(List.of(audience))
                .subject("user-123")
                .issuedAt(expiresAt.minusSeconds(3600))
                .expiresAt(expiresAt)
                .build();
    }

    private static Instant inOneHour() {
        return Instant.now().plusSeconds(3600);
    }

    @Test
    void aceptaAudienceConFormatoApiUri() {
        assertThat(validator.validate(token(ISSUER, "api://" + CLIENT_ID, inOneHour())).hasErrors()).isFalse();
    }

    @Test
    void aceptaAudienceConFormatoGuid() {
        assertThat(validator.validate(token(ISSUER, CLIENT_ID, inOneHour())).hasErrors()).isFalse();
    }

    @Test
    void rechazaAudienceDeOtraApi() {
        assertThat(validator.validate(token(ISSUER, "api://otra-api", inOneHour())).hasErrors()).isTrue();
    }

    @Test
    void rechazaIssuerDeOtroTenant() {
        String otherIssuer = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0";
        assertThat(validator.validate(token(otherIssuer, CLIENT_ID, inOneHour())).hasErrors()).isTrue();
    }

    @Test
    void rechazaTokenExpirado() {
        Instant expiredTwoHoursAgo = Instant.now().minusSeconds(7200);
        assertThat(validator.validate(token(ISSUER, CLIENT_ID, expiredTwoHoursAgo)).hasErrors()).isTrue();
    }
}
