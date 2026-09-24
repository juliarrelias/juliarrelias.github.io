import { sha256Base64Url } from "../_shared/crypto.js";
import { readCookie } from "../_shared/cookies.js";

export async function onRequestGet(context) {
  const sessionId = readCookie(context.request, "__Host-session");

  if (!sessionId) {
    return new Response("Não autenticado", {
      status: 401,
      headers: { "Cache-Control": "no-store" }
    });
  }

  const sessionHash = await sha256Base64Url(sessionId);
  const nowSeconds = Math.floor(Date.now() / 1000);

  const row = await context.env.DB.prepare(
    `SELECT email, display_name
     FROM sessions
     WHERE id_hash = ? AND expires_at > ?`
  )
    .bind(sessionHash, nowSeconds)
    .first();

  if (!row) {
    return new Response("Não autenticado", {
      status: 401,
      headers: { "Cache-Control": "no-store" }
    });
  }

  return Response.json(
    {
      email: row.email,
      displayName: row.display_name
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}
