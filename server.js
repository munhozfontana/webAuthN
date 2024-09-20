const express = require('express');
const path = require('path');
const { Fido2Lib, coerceToArrayBuffer, coerceToBase64Url } = require('fido2-lib');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuração do Fido2Lib
const f2l = new Fido2Lib({
    rpId: "localhost",
    rpName: "My App",
    authenticatorAttachment: "cross-platform",
    authenticatorUserVerification: "preferred",
    cryptoParams: [-7], // ES256
});

// Adicionar e habilitar a extensão appid
const optionGeneratorFn = (extName, type, value) => value;
const resultParserFn = () => { };
const resultValidatorFn = () => { };
f2l.addExtension("appid", optionGeneratorFn, resultParserFn, resultValidatorFn);
f2l.enableExtension("appid");

// Armazenamento simulado de dados de usuário
const users = {};

// Endpoint para gerar as opções de autenticação
app.get('/assertion-options', async (req, res) => {
    const fakeUserId = 'user-id-123'; // ID falso do usuário
    const fakeUserName = 'user@example.com'; // Nome falso de exibição

    // Gerar opções de autenticação
    const authnOptions = await f2l.assertionOptions({
        extensionOptions: {
            appid: "http://localhost:3000", // appid deve ser configurado conforme o domínio
        },
        allowCredentials: [
            {
                id: "lTqW8H/lHJ4yT0nLOvsvKgcyJCeO8LdUjG5vkXpgO2b0XfyjLMejRvW5oslZtA4B/GgkO/qhTgoBWSlDqCng4Q==",
                type: "public-key",
            },
        ],
    });

    // Armazenar o desafio para o usuário
    users[fakeUserId] = {
        id: fakeUserId,
        username: fakeUserName,
        currentChallenge: authnOptions.challenge,
    };

    // Enviar a resposta para o frontend
    res.json({
        ...authnOptions,
        user: {
            id: fakeUserId,
            name: fakeUserName,
        },
    });
});

// Endpoint para verificar a resposta de autenticação
app.post('/verify-authentication', async (req, res) => {
    const { id, rawId, type, response } = req.body;
    const fakeUserId = 'user-id-123'; // ID falso do usuário para simular a autenticação

    const expectedChallenge = users[fakeUserId]?.currentChallenge;

    if (!expectedChallenge) {
        return res.status(400).json({ success: false, message: 'Challenge não encontrado.' });
    }

    try {
        const authnResult = await f2l.assertionResult({
            credential: {
                id,
                rawId: coerceToArrayBuffer(rawId, 'rawId'),
                response: {
                    authenticatorData: coerceToArrayBuffer(response.authenticatorData, 'authenticatorData'),
                    clientDataJSON: coerceToArrayBuffer(response.clientDataJSON, 'clientDataJSON'),
                    signature: coerceToArrayBuffer(response.signature, 'signature'),
                },
                type,
            },
            expectedChallenge,
            expectedOrigin: 'http://localhost:3000',
            expectedRPID: 'localhost',
        });

        if (authnResult.audit.validRequest && authnResult.audit.validExpectations) {
            res.json({ success: true, message: 'Authentication successful!' });
        } else {
            res.status(400).json({ success: false, message: 'Authentication failed.' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
