package cl.andesstay.bff.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifica la derivación del rol Cliente para huéspedes autoregistrados:
 * solo se otorga a invitados (acct = 1) con el scope de la API y sin roles asignados.
 */
class AzureRolesConverterTest {

    private final AzureRolesConverter converter = new AzureRolesConverter();

    private static Jwt token(Consumer<Map<String, Object>> claims) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("user-123")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .claims(claims)
                .build();
    }

    private List<String> authorities(Jwt jwt) {
        return converter.convert(jwt).stream().map(GrantedAuthority::getAuthority).toList();
    }

    @Test
    void invitadoSinRolesConScope_recibeRolCliente() {
        Jwt jwt = token(c -> { c.put("acct", 1L); c.put("scp", "AndesStay.Access"); });
        assertThat(authorities(jwt)).containsExactly("ROLE_Cliente");
    }

    @Test
    void invitadoConAcctComoTexto_recibeRolCliente() {
        Jwt jwt = token(c -> { c.put("acct", "1"); c.put("scp", "openid AndesStay.Access"); });
        assertThat(authorities(jwt)).containsExactly("ROLE_Cliente");
    }

    @Test
    void invitadoSinScopeDeLaApi_quedaSinAuthorities() {
        Jwt jwt = token(c -> { c.put("acct", 1L); c.put("scp", "User.Read"); });
        assertThat(authorities(jwt)).isEmpty();
    }

    @Test
    void miembroSinRoles_quedaSinAuthorities() {
        Jwt jwt = token(c -> { c.put("acct", 0L); c.put("scp", "AndesStay.Access"); });
        assertThat(authorities(jwt)).isEmpty();
    }

    @Test
    void tokenSinClaimAcct_quedaSinAuthorities() {
        Jwt jwt = token(c -> c.put("scp", "AndesStay.Access"));
        assertThat(authorities(jwt)).isEmpty();
    }

    @Test
    void invitadoConRolAsignado_conservaSuRolYNoRecibeCliente() {
        Jwt jwt = token(c -> {
            c.put("acct", 1L);
            c.put("scp", "AndesStay.Access");
            c.put("roles", List.of("Admin"));
        });
        assertThat(authorities(jwt)).containsExactly("ROLE_Admin");
    }

    @Test
    void miembroConRoles_recibeUnaAuthorityPorRol() {
        Jwt jwt = token(c -> { c.put("acct", 0L); c.put("roles", List.of("Operador", "Auditor")); });
        assertThat(authorities(jwt)).containsExactly("ROLE_Operador", "ROLE_Auditor");
    }
}
