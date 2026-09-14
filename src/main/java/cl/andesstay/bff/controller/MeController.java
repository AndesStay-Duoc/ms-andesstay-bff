package cl.andesstay.bff.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Endpoint propio del BFF que devuelve la identidad extraída del JWT ya validado
 * (firma, vigencia, issuer y audience). Sirve para comprobar desde el frontend
 * o Postman qué roles y scopes llegan al backend.
 */
@RestController
@RequestMapping("/api/me")
public class MeController {

    @GetMapping
    @PreAuthorize("hasAnyRole('Admin', 'Operador', 'Cliente', 'Auditor') or hasAuthority('SCOPE_AndesStay.Access')")
    public Mono<Map<String, Object>> me(JwtAuthenticationToken authentication) {
        Jwt jwt = authentication.getToken();
        String scp = jwt.getClaimAsString("scp");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sub", jwt.getSubject());
        body.put("oid", jwt.getClaimAsString("oid"));
        body.put("name", jwt.getClaimAsString("name"));
        body.put("username", jwt.getClaimAsString("preferred_username"));
        body.put("roles", orEmpty(jwt.getClaimAsStringList("roles")));
        body.put("scopes", scp == null ? List.of() : Arrays.asList(scp.split(" ")));
        body.put("authorities", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList());
        body.put("issuer", jwt.getIssuer() != null ? jwt.getIssuer().toString() : null);
        body.put("audience", jwt.getAudience());
        body.put("expiresAt", jwt.getExpiresAt());
        return Mono.just(body);
    }

    private static List<String> orEmpty(List<String> values) {
        return values != null ? values : List.of();
    }
}
