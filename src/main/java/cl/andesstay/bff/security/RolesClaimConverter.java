package cl.andesstay.bff.security;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

/**
 * Traduce un token de cualquiera de los dos tenants a authorities de Spring.
 *
 * <p>Produce dos familias de authorities:
 * <ul>
 *   <li>{@code ROLE_*} a partir del claim {@code roles}, que trae los app roles definidos en
 *       Azure. {@code Recepcionista} se convierte en {@code ROLE_RECEPCIONISTA}.</li>
 *   <li>{@code SCOPE_*} a partir de {@code scp} o {@code scope}, usando el converter estandar
 *       de Spring. Permite exigir {@code SCOPE_access_as_staff} donde corresponda.</li>
 * </ul>
 *
 * <p>Un token sin claim {@code roles} autentica pero queda sin ningun {@code ROLE_*}, asi que
 * toda ruta protegida por rol responde 403. Es deliberado: es mas seguro que un usuario sin
 * rol asignado no pueda hacer nada, y el sintoma apunta directo a la causa, que suele ser
 * haber olvidado asignar el rol en Enterprise applications.
 *
 * <p>Ver docs/contracts/roles.md en el repositorio infra.
 */
public class RolesClaimConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final String CLAIM_ROLES = "roles";
    private static final String PREFIJO_ROL = "ROLE_";

    private final JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>(scopesConverter.convert(jwt));
        authorities.addAll(rolesDesdeClaim(jwt));
        return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    }

    private Collection<GrantedAuthority> rolesDesdeClaim(Jwt jwt) {
        Object claim = jwt.getClaim(CLAIM_ROLES);
        if (!(claim instanceof List<?> valores)) {
            return List.of();
        }
        return valores.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .filter(rol -> !rol.isBlank())
                .map(rol -> PREFIJO_ROL + rol.trim().toUpperCase())
                .distinct()
                .map(SimpleGrantedAuthority::new)
                .map(GrantedAuthority.class::cast)
                .toList();
    }
}
