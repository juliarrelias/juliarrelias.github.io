import { sha256Base64Url } from "../_shared/crypto.js";
import { readCookie, clearSessionCookie } from "../_shared/cookies.js";

export async function onRequestPost(context) {
  // 2. exigir um cabeçalho Origin exatamente igual a PUBLIC_BASE_URL
  const origin = context.request.headers.get("Origin");
  const expectedOrigin = context.env.PUBLIC_BASE_URL;

  if (origin !== expectedOrigin) {
    return new Response("Origem inválida", {
      status: 403,
      headers: { "Cache-Control": "no-store" }
    });
  }

  const sessionId = readCookie(context.request, "__Host-session");

  if (sessionId) {
    const sessionHash = await sha256Base64Url(sessionId);

    // 3. remover a linha da sessão no D1
    await context.env.DB.prepare(
      `DELETE FROM sessions WHERE id_hash = ?`
    )
      .bind(sessionHash)
      .run();
  }

  // 4. expirar o cookie
  const headers = new Headers();
  headers.append("Set-Cookie", clearSessionCookie());
  headers.set("Cache-Control", "no-store");

  // 5. responder
  return new Response(null, { status: 204, headers });
}
