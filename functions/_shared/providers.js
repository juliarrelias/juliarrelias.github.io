export const PROVIDERS = {
  google: {
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    scope: "openid email profile",
    usesNonce: true,
    clientIdEnv: "GOOGLE_CLIENT_ID",
    clientSecretEnv: "GOOGLE_CLIENT_SECRET"
  },
  github: {
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    scope: null,
    usesNonce: false,
    clientIdEnv: "GITHUB_CLIENT_ID",
    clientSecretEnv: "GITHUB_CLIENT_SECRET"
  }
};

export function isValidProvider(provider) {
  return provider === "google" || provider === "github";
}
