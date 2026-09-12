package cl.andesstay.bff.dev;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Emisor de identidad local, <strong>solo para el perfil {@code dev}</strong>.
 *
 * <p>Permite desarrollar y probar el sistema completo sin depender de los tenants de Azure:
 * genera un par de claves RSA al arrancar, publica su JWK set en {@code /dev/jwks} y firma
 * tokens en {@code /dev/token}. El resolver multi-emisor del BFF lo trata como un tenant mas,
 * asi que no hay ninguna rama de codigo distinta entre desarrollo y produccion.
 *
 * <p>La clave se genera en memoria en cada arranque: no hay ningun secreto en el repositorio y
 * los tokens de una ejecucion no sirven en la siguiente.
 *
 * <p>Con el perfil {@code cloud} esta clase no se carga, asi que {@code /dev/token} no existe
 * en lo que se entrega ni en lo que se presenta.
 */
@Configuration
@Profile("dev")
public class DevIssuerConfig {

    /** Issuer del emisor local. Debe coincidir con el configurado en application-dev.yml. */
    public static final String ISSUER = "http://localhost:8080/dev";

    /** Audience de los tokens locales. */
    public static final String AUDIENCE = "api://andesstay-dev";

    @Bean
    RSAKey devRsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair par = generator.generateKeyPair();

        return new RSAKey.Builder((RSAPublicKey) par.getPublic())
                .privateKey((RSAPrivateKey) par.getPrivate())
                .keyID("andesstay-dev")
                .build();
    }

    @Bean
    JWKSet devJwkSet(RSAKey devRsaKey) {
        return new JWKSet(devRsaKey.toPublicJWK());
    }

    /**
     * CORS para desarrollo: el frontend corre en otro puerto que el BFF.
     *
     * <p>En la nube esto lo atiende el API Gateway, por eso el bean existe solo en
     * {@code dev}. Ver docs/contracts/rutas-gateway.md.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:4200"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "OPTIONS"));
        config.setAllowedHeaders(List.of("authorization", "content-type"));
        config.setMaxAge(300L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
