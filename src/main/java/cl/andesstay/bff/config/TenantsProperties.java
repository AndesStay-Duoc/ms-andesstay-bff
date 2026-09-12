package cl.andesstay.bff.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuracion de los emisores de identidad aceptados.
 *
 * <p>AndesStay distingue dos audiencias: el personal (Admin, Recepcionista, Auditor) y los
 * huespedes, que se registran solos. Cada una tiene su propia app registration y por lo tanto
 * su propia audience.
 *
 * <p>Las dos pueden vivir en un mismo tenant o en tenants distintos, y el BFF soporta ambos
 * casos sin cambios de codigo:
 * <ul>
 *   <li><strong>Un tenant, dos apps</strong>: una sola entrada con las dos audiences en
 *       {@code audiences}. Es el caso actual.</li>
 *   <li><strong>Dos tenants</strong>: dos entradas, cada una con su issuer y su audience.</li>
 * </ul>
 *
 * <p>Lo que <strong>no</strong> se puede hacer es declarar dos entradas con el mismo issuer:
 * se indexan por issuer y una sobreescribiria a la otra en silencio. {@code SecurityConfig}
 * detecta ese caso y falla al arrancar con un mensaje explicito.
 *
 * <p>Todo viene de variables de entorno: no hay ningun identificador de tenant en el codigo.
 * Ver docs/contracts/roles.md en el repositorio infra.
 */
@ConfigurationProperties(prefix = "andesstay")
public class TenantsProperties {

    /** Emisores aceptados, indexados por un nombre logico. */
    private Map<String, Tenant> tenants = new LinkedHashMap<>();

    public Map<String, Tenant> getTenants() {
        return tenants;
    }

    public void setTenants(Map<String, Tenant> tenants) {
        this.tenants = tenants;
    }

    public static class Tenant {

        /**
         * Issuer exacto del token, tal como aparece en el claim {@code iss}.
         *
         * <p>Debe copiarse del documento de descubrimiento del tenant, no escribirse de
         * memoria: una barra final de diferencia hace que todo responda 401.
         */
        private String issuerUri;

        /**
         * Audiences aceptadas para este issuer. Son los Application ID URI de las app
         * registrations: {@code api://<client-id>}.
         *
         * <p>Se acepta mas de una porque un mismo tenant puede alojar la aplicacion del
         * personal y la de huespedes. Que la peticion venga de la audiencia correcta para cada
         * grupo de rutas lo garantizan los authorizers del API Gateway, y dentro del BFF lo
         * refuerza el claim {@code scp}.
         */
        private List<String> audiences = new ArrayList<>();

        /**
         * Ubicacion del JWK set. Si se deja vacia, se descubre a partir del issuer.
         *
         * <p>Se completa a mano solo en entornos sin salida a internet o en pruebas.
         */
        private String jwkSetUri;

        public String getIssuerUri() {
            return issuerUri;
        }

        public void setIssuerUri(String issuerUri) {
            this.issuerUri = issuerUri;
        }

        public List<String> getAudiences() {
            return audiences;
        }

        public void setAudiences(List<String> audiences) {
            this.audiences = audiences == null ? new ArrayList<>() : audiences;
        }

        public String getJwkSetUri() {
            return jwkSetUri;
        }

        public void setJwkSetUri(String jwkSetUri) {
            this.jwkSetUri = jwkSetUri;
        }

        /** Audiences no vacias, ignorando entradas en blanco de la configuracion. */
        public List<String> audiencesUtiles() {
            return audiences.stream().filter(a -> a != null && !a.isBlank()).map(String::trim).toList();
        }
    }
}
