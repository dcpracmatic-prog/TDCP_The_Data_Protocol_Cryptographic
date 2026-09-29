# Cuentas de usuario con Supabase

TDCP gestiona las cuentas en el servidor con Better Auth (email y contraseña) sobre Postgres. No hace falta Firebase ni Firestore, y no se guarda ninguna cuenta en `localStorage`.

## Qué hace cada pieza

| Pieza | Dónde |
|---|---|
| Registro, login, logout, sesión, reset de contraseña | `/api/auth/*` → `src/routes/api/auth/$.ts` → `src/lib/auth/server.ts` |
| Hash de contraseñas | scrypt (Better Auth), mínimo 8 caracteres |
| Sesiones | cookie `__Host-` HttpOnly, validada en el servidor en cada request |
| Perfil TDCP (ID `DCP-USR-…`) y carpetas de Drive | tablas `tdcp_profile` y `tdcp_drive_folder` → `src/lib/accounts.functions.ts` |
| Esquema | `migrations/0001_auth.sql`, `0002_tdcp_accounts.sql`, `0003_enable_rls.sql`, `0004_jwks.sql` |
| Identidad ante el Authority | JWT de 5 min (`/api/auth/token`), ver `docs/AUTHORITY_USER_AUTH.md` |
| Correo de restablecimiento | `src/lib/auth/mailer.server.ts` (Resend; en desarrollo, el enlace sale por consola) |

## Configuración con Supabase

1. En Supabase, entra a Connect y copia la cadena del Session pooler (puerto 5432). La conexión directa `db.<ref>.supabase.co` solo funciona por IPv6.
2. Descarga el certificado CA en Database → Settings → SSL Configuration y guárdalo en `certs/supabase-ca.crt`.
3. Crea un archivo `.env` (ya está en `.gitignore`):

   ```env
   VITE_AUTH_ENABLED=true
   DATABASE_URL=postgresql://postgres.adjmeotrqcswvhtzulqw:<PASSWORD>@aws-0-<REGION>.pooler.supabase.com:5432/postgres
   DATABASE_CA_CERT=./certs/supabase-ca.crt
   BETTER_AUTH_SECRET=<openssl rand -hex 32>
   BETTER_AUTH_URL=http://localhost:8080
   # Correo real (verificación + reset) con Resend — mismos nombres que en producción:
   # RESEND_API_KEY=re_...
   # EMAIL_FROM="TDCP <no-reply@tu-dominio.com>"
   # TDCP_REQUIRE_EMAIL_VERIFICATION=false   # true = no se entra sin confirmar el correo
   ```

   Si la contraseña tiene caracteres especiales, codifícalos en la URL (por ejemplo, `@` se escribe `%40`).
4. Crea las tablas con `npm run db:migrate`. El comando es idempotente: registra lo aplicado en `_migrations`.
5. Arranca la app con `npm run dev` y abre http://localhost:8080. Ya puedes usar Crear cuenta, Iniciar sesión y Recuperar.

## Seguridad

- **RLS activado:** `0003_enable_rls.sql` activa Row Level Security sin políticas en todas las tablas. Así, la Data API de Supabase (`anon`/`authenticated`) no puede leer hashes, sesiones ni carpetas, mientras que el servidor, que conecta como `postgres`, funciona igual. No desactives RLS ni crees políticas para `anon` en estas tablas.
- **Consultas acotadas al usuario:** cada función de servidor usa `authMiddleware` y filtra por el id de sesión verificado, nunca por un id enviado desde el cliente.
- **Límite de intentos:** 10 logins por minuto, 5 registros por minuto y 3 resets cada 5 minutos.
- **Reset sin enumeración:** la solicitud responde igual exista o no el correo. El enlace caduca en 30 minutos y, al usarlo, se cierran las demás sesiones.
- **Secretos fuera del código:** se eliminó el secreto OAuth de Grok que venía en el repositorio. El broker de Grok y el header de identidad de Grok quedan desactivados salvo que se configuren por variables de entorno (`GROK_AUTH_CLIENT_ID`/`SECRET`, `GROK_GATE_IDENTITY=true`).

## Pendiente (siguiente fase)

- Verificación de email obligatoria (`requireEmailVerification`) cuando haya un proveedor de correo.
- Las cuentas que ya existían en `localStorage` no se migran; cada usuario debe registrarse de nuevo.
