package cl.andesstay.bff.dev;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Emite tokens firmados localmente, <strong>solo con el perfil {@code dev}</strong>.
 *
 * <p>Sirve para trabajar mientras los tenants de Azure no estan listos, y para probar la
 * autorizacion por rol sin tener que crear un usuario real por cada rol. Los tokens que emite
 * los valida el mismo resolver multi-emisor que valida los de Azure: la ruta de codigo es
 * identica, solo cambia el emisor.
 *
 * <p>Con el perfil {@code cloud} esta clase no se carga y el endpoint no existe.
 */
@RestController
@RequestMapping("/dev")
@Profile("dev")
public class DevTokenController {

    private final RSAKey clave;
    private final JWKSet jwkSet;

    public DevTokenController(RSAKey clave, JWKSet jwkSet) {
        this.clave = clave;
        this.jwkSet = jwkSet;
    }

    /** JWK set publico del emisor local. Es lo que el resource server usa para validar la firma. */
    @GetMapping("/jwks")
    public Map<String, Object> jwks() {
        return jwkSet.toJSONObject();
    }

    /**
     * Firma un token con los roles pedidos.
     *
     * <p>El {@code tenant} determina el claim {@code scp}, imitando lo que emitiria cada tenant
     * real: {@code access_as_staff} o {@code access_as_guest}.
     */
    @PostMapping("/token")
    public ResponseEntity<TokenResponse> token(@RequestBody @jakarta.validation.Valid TokenRequest peticion)
            throws Exception {

        String tenant = (peticion.tenant() == null || peticion.tenant().isBlank())
                ? "staff" : peticion.tenant().trim().toLowerCase();
        long minutos = peticion.expiraEnMinutos() == null ? 60 : peticion.expiraEnMinutos();
        Instant ahora = Instant.now();
        Instant expira = ahora.plusSeconds(minutos * 60);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(DevIssuerConfig.ISSUER)
                .audience(DevIssuerConfig.AUDIENCE)
                .subject(peticion.subject())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(java.util.Date.from(ahora))
                .notBeforeTime(java.util.Date.from(ahora))
                .expirationTime(java.util.Date.from(expira))
                .claim("roles", peticion.roles())
                .claim("scp", "guest".equals(tenant) ? "access_as_guest" : "access_as_staff")
                .claim("name", peticion.subject())
                .claim("tid", "tenant-local-de-desarrollo")
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(clave.getKeyID())
                        .type(JOSEObjectType.JWT)
                        .build(),
                claims);
        jwt.sign(new RSASSASigner(clave.toRSAPrivateKey()));

        return ResponseEntity.ok(new TokenResponse(
                jwt.serialize(), "Bearer", minutos * 60, DevIssuerConfig.AUDIENCE));
    }

    public record TokenRequest(
            @NotEmpty String subject,
            @NotEmpty List<String> roles,
            String tenant,
            @Positive Long expiraEnMinutos) {
    }

    public record TokenResponse(
            String access_token, String token_type, long expires_in, String audience) {
    }
}
