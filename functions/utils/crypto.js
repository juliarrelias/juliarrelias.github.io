export function randomBase64Url() {
    const bytes = new Uint8Array(32);

    crypto.getRandomValues(bytes);

    return btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}


export async function sha256Base64Url(value) {
    const bytes = new TextEncoder().encode(value);

    const digest = await crypto.subtle.digest(
        "SHA-256",
        bytes
    );

    return btoa(
        String.fromCharCode(...new Uint8Array(digest))
    )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}
