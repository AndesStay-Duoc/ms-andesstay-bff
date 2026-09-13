package cl.andesstay.bff.config;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cl.andesstay.bff.security.AudienceValidator;
import cl.andesstay.bff.security.JsonAccessDeniedHandler;
import cl.andesstay.bff.security.JsonAuthenticationEntryPoint;
import cl.andesstay.bff.security.RolesClaimConverter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Seguridad del BFF.
 *
 * <p>El BFF es el unico punto de entrada al dominio, y acepta tokens de los <strong>dos
 * tenants</strong>. Como cada uno tiene su propio issuer y su propia audience, no sirve un solo
 * decoder: se construye un {@link JwtIssuerAuthenticationManagerResolver} que despacha al
 * decoder correcto segun el claim {@code iss} del token.
 *
 * <p>Por cada tenant se validan cuatro cosas:
 * <ol>
 *   <li><strong>Issuer</strong>: mediante {@link JwtValidators#createDefaultWithIssuer}.</li>
 *   <li><strong>Audience</strong>: con {@link AudienceValidator}, porque Spring no lo hace.</li>
 *   <li><strong>Firma</strong>: contra el JWK set del tenant, que Nimbus descarga y cachea.</li>
 *   <li><strong>Vigencia</strong>: {@code exp} y {@code nbf}, incluidos en los validadores por
 *       defecto.</li>
 * </ol>
 *
 * <p>Esta validacion se repite aunque el API Gateway ya la haya hecho. No es redundancia
 * inutil: si alguien alcanza el puerto del BFF sin pasar por el gateway, el backend sigue
 * cerrado.
 */
@Configuration
@EnableConfigurationProperties(TenantsProperties.class)
@EnableMethodSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    private final TenantsProperties tenantsProperties;

    public SecurityConfig(TenantsProperties tenantsProperties) {
        this.tenantsProperties = tenantsProperties;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, ObjectMapper objectMapper,
            AuthenticationManagerResolver<jakarta.servlet.http.HttpServletRequest> resolver) throws Exception {

        JsonAuthenticationEntryPoint entryPoint = new JsonAuthenticationEntryPoint(objectMapper);
        JsonAccessDeniedHandler accessDeniedHandler = new JsonAccessDeniedHandler(objectMapper);

        return http
                // Sin estado: la identidad viaja en el token, no en una sesion de servidor.
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // CSRF no aplica: no hay cookies de sesion que un tercero pueda reutilizar.
                .csrf(csrf -> csrf.disable())
                // En la nube el preflight lo atiende el API Gateway. En dev se usa el bean
                // CorsConfigurationSource que aporta DevIssuerConfig, porque el frontend
                // corre en otro puerto.
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/actuator/health/**").permitAll()
                        .requestMatchers("/dev/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .authenticationManagerResolver(resolver)
                        // Sin esto, un token presente pero invalido lo rechaza el entry point
                        // propio del resource server y la respuesta llega con cuerpo vacio.
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .build();
    }

    /**
     * Resolver que acepta los dos emisores.
     *
     * <p>Un token cuyo {@code iss} no corresponda a ninguno de los tenants configurados no
     * encuentra manager y termina en 401. Eso es lo que hace que un token de huesped presentado
     * contra una ruta de personal sea rechazado.
     */
    @Bean
    AuthenticationManagerResolver<jakarta.servlet.http.HttpServletRequest> tenantAuthenticationManagerResolver() {
        Map<String, AuthenticationManager> porIssuer = new LinkedHashMap<>();

        Map<String, String> nombrePorIssuer = new LinkedHashMap<>();

        tenantsProperties.getTenants().forEach((nombre, tenant) -> {
            // Un emisor sin issuer se ignora: permite trabajar con el perfil dev sin tener
            // configurados los tenants reales, sin ramas de codigo distintas.
            if (tenant.getIssuerUri() == null || tenant.getIssuerUri().isBlank()) {
                log.info("Emisor '{}' sin issuer-uri: no se registra", nombre);
                return;
            }

            List<String> audiences = tenant.audiencesUtiles();
            if (audiences.isEmpty()) {
                throw new IllegalStateException("El emisor '" + nombre
                        + "' tiene issuer-uri pero ninguna audience; sin audience la validacion "
                        + "aceptaria tokens emitidos para otra aplicacion");
            }

            // Los managers se indexan por issuer. Dos entradas con el mismo issuer se
            // sobreescribirian en silencio, dejando una audience sin validar. Cuando el
            // personal y los huespedes viven en un mismo tenant, van en UNA entrada con las
            // dos audiences.
            String yaRegistrado = nombrePorIssuer.get(tenant.getIssuerUri());
            if (yaRegistrado != null) {
                throw new IllegalStateException("Los emisores '" + yaRegistrado + "' y '" + nombre
                        + "' declaran el mismo issuer " + tenant.getIssuerUri()
                        + ". Unificarlos en una sola entrada con varias audiences.");
            }
            nombrePorIssuer.put(tenant.getIssuerUri(), nombre);

            log.info("Emisor '{}' registrado con issuer {} y audiences {}",
                    nombre, tenant.getIssuerUri(), audiences);
            porIssuer.put(tenant.getIssuerUri(), authenticationManagerDe(tenant));
        });

        if (porIssuer.isEmpty()) {
            throw new IllegalStateException(
                    "No hay ningun emisor con issuer-uri en andesstay.tenants. El BFF rechazaria "
                    + "toda peticion. Configurar los emisores reales, o arrancar con el perfil dev.");
        }
        return new JwtIssuerAuthenticationManagerResolver(porIssuer::get);
    }

    private AuthenticationManager authenticationManagerDe(TenantsProperties.Tenant tenant) {
        NimbusJwtDecoder decoder = (tenant.getJwkSetUri() == null || tenant.getJwkSetUri().isBlank())
                ? NimbusJwtDecoder.withIssuerLocation(tenant.getIssuerUri()).build()
                : NimbusJwtDecoder.withJwkSetUri(tenant.getJwkSetUri()).build();

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(tenant.getIssuerUri()),
                new AudienceValidator(tenant.audiencesUtiles())));

        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
        provider.setJwtAuthenticationConverter(new RolesClaimConverter());
        return provider::authenticate;
    }
}
