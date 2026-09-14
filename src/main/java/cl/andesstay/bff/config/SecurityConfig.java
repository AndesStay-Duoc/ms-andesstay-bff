package cl.andesstay.bff.config;

import cl.andesstay.bff.security.AudienceValidator;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Configuración de seguridad del BFF (Backend For Frontend).
 *
 * Responsabilidades:
 *  1. Valida el JWT emitido por Azure AD: firma (JWKS), vigencia (exp/nbf),
 *     issuer y audience. Ver {@link #jwtDecoder}.
 *  2. Mapea el claim "roles" a authorities ROLE_* y el claim "scp" a SCOPE_*.
 *  3. Aplica autorización por rol y método HTTP en cada grupo de rutas según el caso AndesStay.
 *  4. Configura CORS para permitir llamadas desde el frontend Angular.
 *  5. Devuelve respuestas HTTP 401 / 403 en JSON estructurado para que el
 *     frontend pueda distinguir entre "no autenticado" y "sin permisos".
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@EnableConfigurationProperties(OAuth2ResourceServerProperties.class)
public class SecurityConfig {

    // -------------------------------------------------------------------------
    // Roles definidos en el caso AndesStay (valores de App Roles en Azure AD)
    // -------------------------------------------------------------------------
    private static final String ROLE_ADMIN    = "Admin";
    private static final String ROLE_OPERADOR = "Operador";
    private static final String ROLE_CLIENTE  = "Cliente";
    private static final String ROLE_AUDITOR  = "Auditor";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // -------------------------------------------------------------------------
    // Security filter chain principal
    // -------------------------------------------------------------------------
    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http,
                                                      CorsConfigurationSource corsConfigurationSource) {
        http
            // CSRF no aplica en una API stateless con JWT
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)

            // CORS — permite peticiones desde el frontend Angular
            .cors(cors -> cors.configurationSource(corsConfigurationSource))

            // ── Autorización por ruta, método y rol ───────────────────────
            // El orden importa: gana la primera regla que coincide.
            .authorizeExchange(auth -> auth

                // Health check público (Actuator)
                .pathMatchers("/actuator/health", "/actuator/info").permitAll()

                // Preflight OPTIONS (CORS) — sin restricción
                .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                // Perfil del usuario autenticado (claims del token); @PreAuthorize en MeController
                .pathMatchers(HttpMethod.GET, "/api/me").authenticated()

                // Reservas
                //  - Cambiar estado: solo Recepcionista (Operador) y Admin
                .pathMatchers(HttpMethod.PUT, "/api/reservations/*/status")
                    .hasAnyRole(ROLE_ADMIN, ROLE_OPERADOR)
                //  - Crear: Huésped (Cliente), Recepcionista y Admin
                .pathMatchers(HttpMethod.POST, "/api/reservations")
                    .hasAnyRole(ROLE_ADMIN, ROLE_OPERADOR, ROLE_CLIENTE)
                //  - Listar con filtros: Admin y Operador
                .pathMatchers(HttpMethod.GET, "/api/reservations")
                    .hasAnyRole(ROLE_ADMIN, ROLE_OPERADOR)
                //  - Detalle: todos los roles (ms-reservations valida que el Cliente sea dueño)
                .pathMatchers(HttpMethod.GET, "/api/reservations/*")
                    .hasAnyRole(ROLE_ADMIN, ROLE_OPERADOR, ROLE_CLIENTE, ROLE_AUDITOR)
                .pathMatchers("/api/reservations/**")
                    .hasAnyRole(ROLE_ADMIN, ROLE_OPERADOR)

                // Catálogo
                //  - Endpoints internos entre microservicios: nunca expuestos por el BFF
                .pathMatchers("/api/catalog/internal/**").denyAll()
                //  - Lectura: Admin y Operador
                .pathMatchers(HttpMethod.GET, "/api/catalog/**")
                    .hasAnyRole(ROLE_ADMIN, ROLE_OPERADOR)
                //  - Escritura (POST/PUT/DELETE): solo Admin
                .pathMatchers("/api/catalog/**")
                    .hasRole(ROLE_ADMIN)

                // Reportería: solo Admin, solo lectura
                .pathMatchers(HttpMethod.GET, "/api/report/**")
                    .hasRole(ROLE_ADMIN)
                .pathMatchers("/api/report/**").denyAll()

                // Auditoría: Admin y Auditor, solo lectura
                .pathMatchers(HttpMethod.GET, "/api/audit/**")
                    .hasAnyRole(ROLE_ADMIN, ROLE_AUDITOR)
                .pathMatchers("/api/audit/**").denyAll()

                // Cualquier otra ruta requiere autenticación
                .anyExchange().authenticated()
            )

            // ── OAuth2 Resource Server — valida el JWT de Azure AD ─────────
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter()))
                // 401 dentro del flujo JWT (token ausente, expirado, firma/iss/aud inválidos)
                .authenticationEntryPoint(authenticationEntryPoint())
                .accessDeniedHandler(accessDeniedHandler())
            )

            // ── Manejadores de error HTTP ──────────────────────────────────
            .exceptionHandling(ex -> ex
                // 401: no autenticado
                .authenticationEntryPoint(authenticationEntryPoint())
                // 403: autenticado pero sin el rol requerido
                .accessDeniedHandler(accessDeniedHandler())
            );

        return http.build();
    }

    // -------------------------------------------------------------------------
    // Decoder JWT explícito:
    //  - Firma: claves públicas JWKS de Azure AD (jwk-set-uri)
    //  - Vigencia: exp / nbf (JwtTimestampValidator, tolerancia 60 s)
    //  - Issuer: https://login.microsoftonline.com/<TENANT_ID>/v2.0
    //  - Audience: api://<CLIENT_ID> o <CLIENT_ID>
    // -------------------------------------------------------------------------
    @Bean
    public ReactiveJwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
        OAuth2ResourceServerProperties.Jwt jwtProps = properties.getJwt();
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder
                .withJwkSetUri(jwtProps.getJwkSetUri())
                .build();
        decoder.setJwtValidator(jwtValidator(jwtProps.getIssuerUri(), jwtProps.getAudiences()));
        return decoder;
    }

    /** Validadores aplicados a cada token (público y estático para poder testearlo). */
    public static OAuth2TokenValidator<Jwt> jwtValidator(String issuerUri, List<String> audiences) {
        return new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuerUri),   // exp, nbf e iss
                new AudienceValidator(audiences)                    // aud
        );
    }

    // -------------------------------------------------------------------------
    // Conversión de claims → GrantedAuthorities
    //  - "roles" → ROLE_Admin, ROLE_Operador... (permite hasRole / hasAnyRole)
    //  - "scp"   → SCOPE_AndesStay.Access       (permite hasAuthority('SCOPE_...'))
    // -------------------------------------------------------------------------
    @Bean
    public ReactiveJwtAuthenticationConverterAdapter jwtAuthConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter());
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }

    /** Convierte roles y scopes del token en authorities (público y estático para los tests). */
    public static Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter() {
        JwtGrantedAuthoritiesConverter rolesConverter = new JwtGrantedAuthoritiesConverter();
        rolesConverter.setAuthoritiesClaimName("roles");   // claim de App Roles de Azure AD
        rolesConverter.setAuthorityPrefix("ROLE_");

        JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();
        scopesConverter.setAuthoritiesClaimName("scp");    // scopes delegados del access token
        scopesConverter.setAuthorityPrefix("SCOPE_");

        return jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>(rolesConverter.convert(jwt));
            authorities.addAll(scopesConverter.convert(jwt));
            return authorities;
        };
    }

    // -------------------------------------------------------------------------
    // CORS — permite al frontend Angular hacer llamadas al BFF
    // -------------------------------------------------------------------------
    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${andesstay.security.cors-allowed-origins:http://localhost:4200}") List<String> allowedOrigins) {
        CorsConfiguration config = new CorsConfiguration();

        // Orígenes permitidos: se configuran con CORS_ALLOWED_ORIGINS (separados por coma)
        config.setAllowedOrigins(allowedOrigins);

        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

        // Authorization es obligatorio para que MSAL pueda enviar el Bearer token
        config.setAllowedHeaders(List.of(
            "Authorization",
            "Content-Type",
            "Accept",
            "X-Requested-With",
            "Cache-Control"
        ));

        // Permite al navegador leer el detalle del error Bearer
        config.setExposedHeaders(List.of(HttpHeaders.WWW_AUTHENTICATE));

        // El JWT viaja en la cabecera Authorization; no se usan cookies
        config.setAllowCredentials(false);

        // Tiempo de caché del preflight en segundos
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // -------------------------------------------------------------------------
    // 401 — token ausente, expirado, con firma inválida o iss/aud incorrectos
    // -------------------------------------------------------------------------
    @Bean
    public ServerAuthenticationEntryPoint authenticationEntryPoint() {
        return (exchange, ex) -> {
            boolean invalidToken = ex instanceof InvalidBearerTokenException;
            // RFC 6750: el 401 de un recurso protegido con Bearer incluye WWW-Authenticate
            exchange.getResponse().getHeaders().set(HttpHeaders.WWW_AUTHENTICATE,
                invalidToken ? "Bearer error=\"invalid_token\"" : "Bearer");

            return writeJson(exchange, HttpStatus.UNAUTHORIZED,
                invalidToken
                    ? "Token de acceso inválido o expirado."
                    : "Token de acceso ausente. Inicia sesión con Microsoft.");
        };
    }

    // -------------------------------------------------------------------------
    // 403 — autenticado pero sin el rol requerido para la ruta
    // -------------------------------------------------------------------------
    @Bean
    public ServerAccessDeniedHandler accessDeniedHandler() {
        return (exchange, ex) -> {
            exchange.getResponse().getHeaders().set(HttpHeaders.WWW_AUTHENTICATE,
                "Bearer error=\"insufficient_scope\"");
            return writeJson(exchange, HttpStatus.FORBIDDEN,
                "No tienes los permisos necesarios para acceder a este recurso.");
        };
    }

    // -------------------------------------------------------------------------
    // Helper: serializa el cuerpo de error a JSON y lo escribe en la respuesta
    // -------------------------------------------------------------------------
    private Mono<Void> writeJson(ServerWebExchange exchange, HttpStatus status, String message) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        body.put("path", exchange.getRequest().getPath().value());

        byte[] bytes;
        try {
            bytes = MAPPER.writeValueAsBytes(body);
        } catch (Exception e) {
            bytes = "{\"error\":\"Internal error serializing response\"}".getBytes(StandardCharsets.UTF_8);
        }
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
