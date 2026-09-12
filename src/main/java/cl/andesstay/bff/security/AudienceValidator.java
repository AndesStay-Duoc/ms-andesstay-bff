package cl.andesstay.bff.security;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Valida el claim {@code aud} del token contra las audiences aceptadas.
 *
 * <p>Spring Security <strong>no valida el audience por defecto</strong>: sus validadores
 * estandar cubren issuer, firma y vigencia, pero no a quien va dirigido el token. Sin esto, un
 * token legitimo emitido por el mismo tenant para otra aplicacion seria aceptado.
 *
 * <p>En la practica el sintoma es un login que se ve perfecto y un backend que deberia
 * rechazarlo: si el frontend pide un scope de Microsoft Graph en vez del propio, el token llega
 * con {@code aud} de Graph. Este validador es el que lo detiene.
 *
 * <p>Acepta varias audiences porque un mismo tenant puede alojar la aplicacion del personal y
 * la de huespedes. Que cada grupo de rutas reciba solo su audiencia lo garantizan los
 * authorizers del API Gateway; dentro del BFF, el claim {@code scp} distingue una de otra.
 */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private static final String ERROR_CODE = "invalid_token";

    private final Set<String> audiencesAceptadas;

    public AudienceValidator(Collection<String> audiencesAceptadas) {
        Set<String> limpias = audiencesAceptadas == null
                ? Set.of()
                : audiencesAceptadas.stream()
                        .filter(a -> a != null && !a.isBlank())
                        .map(String::trim)
                        .collect(java.util.stream.Collectors.toUnmodifiableSet());

        if (limpias.isEmpty()) {
            throw new IllegalArgumentException(
                    "Hay que declarar al menos una audience: un validador sin audiences "
                    + "aceptaria tokens emitidos para cualquier aplicacion");
        }
        this.audiencesAceptadas = limpias;
    }

    /** Conveniencia para el caso de una sola audience. */
    public AudienceValidator(String audienceEsperada) {
        this(List.of(audienceEsperada == null ? "" : audienceEsperada));
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        List<String> delToken = token.getAudience() == null ? List.of() : token.getAudience();

        if (delToken.stream().anyMatch(audiencesAceptadas::contains)) {
            return OAuth2TokenValidatorResult.success();
        }

        OAuth2Error error = new OAuth2Error(
                ERROR_CODE,
                "El token no esta dirigido a esta API. Audiences aceptadas: " + audiencesAceptadas,
                "https://tools.ietf.org/html/rfc6750#section-3.1");
        return OAuth2TokenValidatorResult.failure(error);
    }
}
