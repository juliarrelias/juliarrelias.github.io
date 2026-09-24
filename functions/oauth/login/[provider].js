import { randomValue, sha256Base64Url } from "../../_shared/crypto.js";
import { PROVIDERS, isValidProvider } from "../../_shared/providers.js";
import { buildTransactionCookie } from "../../_shared/cookies.js";

export async function onRequestGet(context) {
  const provider = context.params.provider;

  // 1. aceitar somente google ou github
  if (!isValidProvider(provider)) {
    return new Response("Not found", { status: 404 });
  }

  const config = PROVIDERS[provider];
  const baseUrl = context.env.PUBLIC_BASE_URL;
  const clientId =
    provider === "google"
      ? context.env.GOOGLE_CLIENT_ID
      : context.env.GITHUB_CLIENT_ID;

  // Gera os valores aleatórios desta transação
  const txId = randomValue();
  const state = randomValue();
  const codeVerifier = randomValue();
  const nonce = config.usesNonce ? randomValue() : null;

  // Calcula os resumos que vão para o banco
  const idHash = await sha256Base64Url(txId);
  const stateHash = await sha256Base64Url(state);
  const codeChallenge = await sha256Base64Url(codeVerifier);

  const expiresAt = Math.floor(Date.now() / 1000) + 600; // 10 minutos

  // 2. gravar a transação no D1
  await context.env.DB.prepare(
    `INSERT INTO oauth_transactions
     (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(idHash, provider, stateHash, nonce, codeVerifier, expiresAt)
    .run();

  // 3. criar o cookie temporário
  const cookie = buildTransactionCookie(txId);

  // 4. montar o pedido de autorização
  const redirectUri = `${baseUrl}/oauth/callback/${provider}`;
  const authUrl = new URL(config.authorizationEndpoint);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  if (config.scope) {
    authUrl.searchParams.set("scope", config.scope);
  }
  if (nonce) {
    authUrl.searchParams.set("nonce", nonce);
  }

  // 5. responder com um redirecionamento 302
  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      "Set-Cookie": cookie
    }
  });
}
