document.getElementById('authenticate').addEventListener('click', async () => {
    try {
        const optionsResponse = await fetch('/assertion-options');
        const options = await optionsResponse.json();

        const publicKey = {
            ...options,
            challenge: coerceToArrayBuffer(options.challenge, 'challenge'),
            allowCredentials: options.allowCredentials.map(cred => ({
                ...cred,
                id: coerceToArrayBuffer(cred.id, 'id'),
            })),
        };

        const credential = await navigator.credentials.get({ publicKey });

        const authnResponse = {
            id: credential.id,
            rawId: coerceToBase64Url(credential.rawId, 'rawId'),
            response: {
                authenticatorData: coerceToBase64Url(credential.response.authenticatorData, 'authenticatorData'),
                clientDataJSON: coerceToBase64Url(credential.response.clientDataJSON, 'clientDataJSON'),
                signature: coerceToBase64Url(credential.response.signature, 'signature'),
            },
            type: credential.type,
        };

        const verifyResponse = await fetch('/verify-authentication', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(authnResponse)
        });

        const verifyResult = await verifyResponse.json();
        document.getElementById('result').textContent = JSON.stringify(verifyResult, null, 2);
    } catch (error) {
        console.error(error);
        document.getElementById('result').textContent = 'Error during authentication.';
    }
});

function coerceToArrayBuffer(value, type) {
    if (typeof value === 'string') {
        return Uint8Array.from(atob(value), c => c.charCodeAt(0)).buffer;
    }
    return value;
}

function coerceToBase64Url(value, type) {
    return btoa(String.fromCharCode(...new Uint8Array(value)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}
