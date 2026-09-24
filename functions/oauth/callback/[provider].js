import { sha256Base64Url, randomValue } from "../../_shared/crypto.js";
import { isValidProvider } from "../../_shared/providers.js";
import {
  readCookie,
  clearTransactionCookie,
  buildSessionCookie
} from "../../_shared/cookies.js";
import { exchangeCodeForToken, confirmIdentity } from "../../_shared/oidc.js";

export async function onRequestGet(context) {
  const provider = context.params.provider;

  if (!isValidProvider(provider)) {
    return new Response("Not found", { status: 404 });
  }

  const url = new URL(context.request.url);
  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  // 1. recusar error ou a ausência de code e state
  if (error || !code || !state) {
    return new Response("Requisição inválida", {
      status: 400,
      headers: { "Cache-Control": "no-store" }
    });
  }

  // 2. exigir o cookie __Host-oauth-tx
  const txId = readCookie(context.request, "__Host-oauth-tx");
  if (!txId) {
    return new Response("Transação ausente", {
      status: 400,
      headers: { "Cache-Control": "no-store" }
    });
  }

  // 3. calcular o resumo e localizar uma transação não expirada
  const idHash = await sha256Base64Url(txId);
  const nowSeconds = Math.floor(Date.now() / 1000);

  const row = await context.env.DB.prepare(
    `SELECT state_hash, nonce, code_verifier, provider
     FROM oauth_transactions
     WHERE id_hash = ? AND expires_at > ?`
  )
    .bind(idHash, nowSeconds)
    .first();

  if (!row || row.provider !== provider) {
    return new Response("Transação inválida ou expirada", {
      status: 400,
      headers: { "Cache-Control": "no-store" }
    });
  }

  // 4. comparar o resumo de state com o valor conservado no D1
  const stateHash = await sha256Base64Url(state);
  if (stateHash !== row.state_hash) {
    return new Response("State inválido", {
      status: 400,
      headers: { "Cache-Control": "no-store" }
    });
  }

  // 5. apagar a transação antes de concluir o fluxo
  await context.env.DB.prepare(
    `DELETE FROM oauth_transactions WHERE id_hash = ?`
  )
    .bind(idHash)
    .run();

  const baseUrl = context.env.PUBLIC_BASE_URL;
  const redirectUri = `${baseUrl}/oauth/callback/${provider}`;

  // 6. trocar o código com o code_verifier e o Client Secret do provedor
  const tokenResponse = await exchangeCodeForToken(context, provider, {
    code,
    codeVerifier: row.code_verifier,
    redirectUri
  });

  // 7. validar a resposta de identidade conforme o contrato do provedor
  const identity = await confirmIdentity(context, provider, tokenResponse, {
    nonce: row.nonce
  });

  // 8. criar uma sessão opaca
  const sessionId = randomValue();
  const sessionHash = await sha256Base64Url(sessionId);
  const sessionExpiresAt = nowSeconds + 8 * 60 * 60; // 8 horas

  await context.env.DB.prepare(
    `INSERT INTO sessions
     (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      sessionHash,
      identity.issuer,
      identity.subject,
      identity.email ?? null,
      identity.displayName ?? null,
      sessionExpiresAt,
      nowSeconds
    )
    .run();

  // 9. limpar o cookie temporário e criar o cookie de sessão
  const headers = new Headers();
  headers.append("Set-Cookie", clearTransactionCookie());
  headers.append("Set-Cookie", buildSessionCookie(sessionId));
  headers.set("Cache-Control", "no-store");
  headers.set("Location", baseUrl);

  // 10. redirecionar para PUBLIC_BASE_URL
  return new Response(null, { status: 302, headers });
}
