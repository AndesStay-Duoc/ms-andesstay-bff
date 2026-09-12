# ms-andesstay-bff

**Backend for Frontend** de AndesStay. Único punto de entrada al dominio: el frontend nunca
llama directo a un microservicio.

## Qué hace

Recibe las peticiones que llegan desde el API Gateway, valida el token, autoriza por rol y
delega en el microservicio de dominio correspondiente.

El camino seguro es siempre:

```
JWT → API Gateway → ms-andesstay-bff → microservicio de dominio
```

## Validación de identidad

AndesStay usa **dos tenants**: el corporativo para Admin, Recepcionista y Auditor, y uno de
Entra External ID para huéspedes con auto-registro. Cada uno emite tokens con su propio issuer
y audience, así que el BFF no puede usar un solo decoder.

`SecurityConfig` arma un `JwtIssuerAuthenticationManagerResolver` que despacha al decoder
correcto según el claim `iss`. Por cada tenant valida cuatro cosas:

| Qué | Cómo |
|---|---|
| **Issuer** | `JwtValidators.createDefaultWithIssuer` |
| **Audience** | `AudienceValidator` propio — **Spring no lo valida por defecto** |
| **Firma** | Contra el JWK set del tenant, que Nimbus descarga y cachea |
| **Vigencia** | `exp` y `nbf`, incluidos en los validadores por defecto |

Un token cuyo `iss` no corresponda a ningún tenant configurado no encuentra manager y termina
en `401`. Eso es lo que hace que un token de huésped presentado contra una ruta de personal sea
rechazado.

La validación se repite aunque el API Gateway ya la haya hecho. No es redundancia inútil: si
alguien alcanza el puerto del BFF sin pasar por el gateway, el backend sigue cerrado.

## Códigos de respuesta

| Situación | Código |
|---|---|
| Sin cabecera `Authorization` | `401` |
| Token de un issuer desconocido | `401` |
| Firma inválida | `401` |
| Token expirado | `401` |
| Audience incorrecta | `401` |
| Token válido, rol sin permiso | `403` |
| Token válido y autorizado | `200` |

`401` significa "no sé quién eres"; `403`, "sé quién eres y no puedes". La distinción es
explícita: `JsonAuthenticationEntryPoint` y `JsonAccessDeniedHandler` devuelven JSON
consistente, sin filtrar detalles internos.

## Roles

El claim `roles` se traduce a authorities anteponiendo `ROLE_` y pasando a mayúsculas:

| Claim en Azure | Authority |
|---|---|
| `Admin` | `ROLE_ADMIN` |
| `Recepcionista` | `ROLE_RECEPCIONISTA` |
| `Auditor` | `ROLE_AUDITOR` |
| `Huesped` | `ROLE_HUESPED` |

El scope también se expone como `SCOPE_access_as_staff` o `SCOPE_access_as_guest`.

Un token sin claim `roles` autentica pero queda sin ningún `ROLE_`, así que toda ruta protegida
responde `403`. Es deliberado, y el síntoma apunta directo a la causa habitual: olvidar asignar
el rol en *Enterprise applications*.

La matriz completa de endpoint por rol está en
[`infra/docs/contracts/roles.md`](https://github.com/AndesStay-Duoc/infra/blob/develop/docs/contracts/roles.md).

## Endpoints

| Método | Ruta | Rol |
|---|---|---|
| `GET` | `/api/reservations` | Admin, Recepcionista, Huésped |
| `GET` | `/api/reservations/whoami` | Cualquier autenticado |
| `GET` | `/actuator/health` | público |

`/api/reservations` devuelve datos de ejemplo por ahora: alcanza para probar las rutas del API
Gateway antes de que el dominio exista. `whoami` devuelve los claims del token y sirve para
demostrar que los roles se leen del token y no están escritos en el código.

## Stack

Java 21 · Spring Boot 3.5.3 · Spring Security OAuth2 Resource Server · Maven Wrapper.

> El plan inicial apuntaba a Spring Boot 4.x, pero Maven Central no publica todavía ninguna
> versión 4: la más reciente de `spring-boot-starter-parent` es 3.5.3. Se fijó esa.

## Variables de entorno

| Variable | Descripción |
|---|---|
| `SERVER_PORT` | Puerto. Por defecto `8080` |
| `JWT_ISSUER_STAFF` | Issuer del tenant corporativo |
| `JWT_AUDIENCE_STAFF` | Audience esperada: `api://<staff-client-id>` |
| `JWT_ISSUER_GUEST` | Issuer del tenant de huéspedes |
| `JWT_AUDIENCE_GUEST` | Audience esperada: `api://<guest-client-id>` |
| `SVC_*_URL` | URLs de los microservicios de dominio |
| `LOG_LEVEL_SECURITY` | `DEBUG` para ver por qué se rechazó un token |

Se configuran en un `.env` que **no se versiona**. Ver `.env.example`.

Los valores se obtienen siguiendo
[`infra/docs/guias/azure-identidad.md`](https://github.com/AndesStay-Duoc/infra/blob/develop/docs/guias/azure-identidad.md).
El issuer hay que copiarlo del documento de descubrimiento del tenant, no escribirlo de
memoria: una barra final de diferencia hace que todo responda `401`.

## Cómo levantarlo

```bash
./mvnw spring-boot:run
```

Requiere las cuatro variables de identidad. Sin ellas el arranque falla de inmediato con un
mensaje explícito, en vez de quedar aceptando cualquier token.

Verificar que responde:

```bash
curl -i http://localhost:8080/api/reservations
```

Debe devolver `401` con cuerpo JSON. Con un token válido, `200` y la lista.

## Tests

```bash
./mvnw test
```

Cubren la validación de audience, incluido el caso de un token emitido para Microsoft Graph, y
la traducción de claims a authorities.

## Cómo contribuir

Ver [`CONTRIBUTING.md`](CONTRIBUTING.md).
