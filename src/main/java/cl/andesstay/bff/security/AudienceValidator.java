package cl.andesstay.bff.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * Valida que el claim "aud" del JWT contenga al menos una de las audiencias
 * aceptadas por el BFF.
 *
 * Azure AD emite el aud según requestedAccessTokenVersion del manifest: los
 * tokens v1 traen "api://<clientId>" y los v2 traen el GUID del clientId. Se
 * aceptan ambos formatos, pero el issuer configurado es el de v2, por lo que la
 * app registration debe fijar requestedAccessTokenVersion = 2.
 */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error INVALID_AUDIENCE = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_TOKEN,
            "El token no está emitido para esta API (audience inválido).",
            null);

    private final Set<String> allowedAudiences;

    public AudienceValidator(Collection<String> allowedAudiences) {
        if (allowedAudiences == null || allowedAudiences.isEmpty()) {
            throw new IllegalArgumentException("Debe configurarse al menos un audience permitido");
        }
        this.allowedAudiences = Set.copyOf(allowedAudiences);
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> audiences = jwt.getAudience();
        if (audiences != null && audiences.stream().anyMatch(allowedAudiences::contains)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(INVALID_AUDIENCE);
    }
}
