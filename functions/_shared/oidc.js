import { PROVIDERS } from "./providers.js";

// ---------- Troca do código por token (passo 6) ----------

export async function exchangeCodeForToken(context, provider, { code, codeVerifier, redirectUri }) {
  const config = PROVIDERS[provider];
  const clientId = context.env[config.clientIdEnv];
  const clientSecret = context.env[config.clientSecretEnv];

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
    code_verifier: codeVerifier
  });

  const response = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json"
    },
    body: body.toString()
  });

  if (!response.ok) {
    throw new Error("Falha ao trocar o código por token");
  }

  return response.json();
}

// ---------- Confirmação de identidade (passo 7) ----------

export async function confirmIdentity(context, provider, tokenResponse, { nonce }) {
  if (provider === "google") {
    return confirmGoogleIdentity(context, tokenResponse, nonce);
  }
  if (provider === "github") {
    return confirmGithubIdentity(context, tokenResponse);
  }
  throw new Error("Provedor desconhecido");
}

async function confirmGoogleIdentity(context, tokenResponse, expectedNonce) {
  const idToken = tokenResponse.id_token;
  if (!idToken) {
    throw new Error("Resposta do Google sem id_token");
  }

  // 1. separar as três partes do JWT
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw new Error("Formato de id_token inválido");
  }
  const [headerPart, payloadPart, signaturePart] = parts;

  // 2. decodificar o cabeçalho e exigir alg RS256
  const header = base64UrlDecodeJson(headerPart);
  if (header.alg !== "RS256") {
    throw new Error("Algoritmo de assinatura inesperado");
  }

  // 3. obter o documento de descoberta OIDC
  const discoveryResponse = await fetch(
    "https://accounts.google.com/.well-known/openid-configuration"
  );
  const discovery = await discoveryResponse.json();

  // 4. obter o JWKS
  const jwksResponse = await fetch(discovery.jwks_uri);
  const jwks = await jwksResponse.json();

  // 5. selecionar a chave pelo kid
  const jwk = jwks.keys.find((key) => key.kid === header.kid);
  if (!jwk) {
    throw new Error("Chave pública não encontrada no JWKS");
  }

  // 6. importar a JWK
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  // 7. verificar a assinatura
  const signingInput = `${headerPart}.${payloadPart}`;
  const signatureBytes = base64UrlDecode(signaturePart);
  const encoder = new TextEncoder();

  const isValidSignature = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signatureBytes,
    encoder.encode(signingInput)
  );

  if (!isValidSignature) {
    throw new Error("Assinatura do id_token inválida");
  }

  // 8. validar iss, aud, exp, iat e nonce
  const payload = base64UrlDecodeJson(payloadPart);
  const nowSeconds = Math.floor(Date.now() / 1000);

  if (payload.iss !== discovery.issuer && payload.iss !== "https://accounts.google.com") {
    throw new Error("Emissor inválido");
  }
  if (payload.aud !== context.env.GOOGLE_CLIENT_ID) {
    throw new Error("Audiência inválida");
  }
  if (!payload.exp || payload.exp < nowSeconds) {
    throw new Error("Token expirado");
  }
  if (!payload.iat || payload.iat > nowSeconds + 60) {
    throw new Error("Token emitido no futuro");
  }
  if (expectedNonce && payload.nonce !== expectedNonce) {
    throw new Error("Nonce inválido");
  }

  return {
    issuer: payload.iss,
    subject: payload.sub,
    email: payload.email ?? null,
    displayName: payload.name ?? null
  };
}

async function confirmGithubIdentity(context, tokenResponse) {
  // 9. exigir access_token e token_type Bearer
  const accessToken = tokenResponse.access_token;
  const tokenType = tokenResponse.token_type;

  if (!accessToken || !/^bearer$/i.test(tokenType ?? "")) {
    throw new Error("Resposta do GitHub sem access_token válido");
  }

  // 10. consultar /user
  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2026-03-10",
      "User-Agent": "oauth-pages-lab"
    }
  });

  if (userResponse.status !== 200) {
    throw new Error("Falha ao consultar o perfil no GitHub");
  }

  const profile = await userResponse.json();
  if (typeof profile.id !== "number") {
    throw new Error("Resposta do GitHub sem id numérico");
  }

  // Revogar a autorização concedida à OAuth App
  const clientId = context.env.GITHUB_CLIENT_ID;
  const clientSecret = context.env.GITHUB_CLIENT_SECRET;
  const basicAuth = btoa(`${clientId}:${clientSecret}`);

  const revokeResponse = await fetch(
    `https://api.github.com/applications/${clientId}/grant`,
    {
      method: "DELETE",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "Content-Type": "application/json",
        "User-Agent": "oauth-pages-lab"
      },
      body: JSON.stringify({ access_token: accessToken })
    }
  );

  if (revokeResponse.status !== 204) {
    throw new Error("Falha ao revogar a autorização do GitHub");
  }

  return {
    issuer: "https://github.com",
    subject: String(profile.id),
    email: profile.email ?? null,
    displayName: profile.name ?? profile.login ?? null
  };
}

// ---------- Utilitários de Base64URL ----------

function base64UrlDecode(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = padded.length % 4 === 0 ? 0 : 4 - (padded.length % 4);
  const withPadding = padded + "=".repeat(padLength);
  const binary = atob(withPadding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlDecodeJson(str) {
  const bytes = base64UrlDecode(str);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text);
}
