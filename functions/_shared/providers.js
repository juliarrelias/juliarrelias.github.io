export const PROVIDERS = {
  google: {
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    scope: "openid email profile",
    usesNonce: true
  },
  github: {
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    scope: null,
    usesNonce: false
  }
};

export function isValidProvider(provider) {
  return provider === "google" || provider === "github";
}
