// =================================================================
// DRONGO AUTONOMOUS - WEBAUTHN BACKEND SERVER
// =================================================================
// This server handles all the logic for registering and authenticating
// users via fingerprint, Face ID, or other device authenticators.
// It is designed to be deployed on a platform like Render.

// --- 1. Import necessary libraries ---
const express = require('express');
const cors = require('cors');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(express.json()); // Middleware to parse JSON request bodies

// --- 2. Configure CORS ---
// For security, we must specify which website is allowed to communicate
// with this server. In production, this should be your live website's URL.

// ===============================================================
// === FIX: ADD YOUR GITHUB PAGES URL TO THIS "GUEST LIST" ARRAY ===
// ===============================================================
const allowedOrigins = [
    'https://eugeneasande.github.io', // <<< YOUR FRONT-END URL
    'https://drongo-login.onrender.com', 
    'http://127.0.0.1:5500',
    'http://localhost:5500'
];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true,
}));


// --- 3. In-Memory "Database" for Demonstration ---
const users = {}; 
const challenges = {};

// --- 4. WebAuthn Configuration ---
const rpName = 'DRONGO AUTONOMOUS';
const rpID = 'drongo-auth-server.onrender.com'; // This should be your Render app's domain
const origin = `https://${rpID}`;

// =================================================================
// --- 5. API Endpoints ---
// =================================================================

// A. REGISTRATION ENDPOINTS
app.post('/generate-registration-options', (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username is required' });
    if (!users[username]) {
        users[username] = { id: `user_${Date.now()}`, username, authenticators: [] };
    }
    const user = users[username];
    const options = generateRegistrationOptions({
        rpName, rpID, userID: user.id, userName: user.username, attestationType: 'none',
        excludeCredentials: user.authenticators.map(auth => ({
            id: auth.credentialID, type: 'public-key', transports: auth.transports,
        })),
    });
    challenges[user.id] = options.challenge;
    res.json(options);
});

app.post('/verify-registration', async (req, res) => {
    const { username, response } = req.body;
    const user = users[username];
    if (!user || !challenges[user.id]) return res.status(400).json({ error: 'User or challenge not found.' });
    const expectedChallenge = challenges[user.id];
    try {
        const verification = await verifyRegistrationResponse({
            response, expectedChallenge, expectedOrigin: 'https://eugeneasande.github.io', expectedRPID: rpID,
        });
        const { verified, registrationInfo } = verification;
        if (verified && registrationInfo) {
            const { credentialPublicKey, credentialID, counter } = registrationInfo;
            users[username].authenticators.push({
                credentialID, credentialPublicKey, counter, transports: response.response.transports || [],
            });
            res.json({ verified: true });
        } else {
            res.status(400).json({ error: 'Could not verify registration.' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    } finally {
        delete challenges[user.id];
    }
});

// B. AUTHENTICATION (LOGIN) ENDPOINTS
app.post('/generate-authentication-options', (req, res) => {
    const { username } = req.body;
    const user = users[username];
    if (!user || user.authenticators.length === 0) {
        return res.status(400).json({ error: 'User not found or has no registered authenticators.' });
    }
    const options = generateAuthenticationOptions({
        allowCredentials: user.authenticators.map(auth => ({
            id: auth.credentialID, type: 'public-key', transports: auth.transports,
        })),
        userVerification: 'preferred',
    });
    challenges[user.id] = options.challenge;
    res.json(options);
});

app.post('/verify-authentication', async (req, res) => {
    const { username, response } = req.body;
    const user = users[username];
    if (!user || !challenges[user.id]) return res.status(400).json({ error: 'User or challenge not found.' });
    const expectedChallenge = challenges[user.id];
    const authenticator = user.authenticators.find(auth => auth.credentialID.toString() === response.id);
    if (!authenticator) return res.status(400).json({ error: 'Authenticator not recognized.' });
    try {
        const verification = await verifyAuthenticationResponse({
            response, expectedChallenge, expectedOrigin: 'https://eugeneasande.github.io', expectedRPID: rpID, authenticator,
        });
        const { verified, authenticationInfo } = verification;
        if (verified) {
            authenticator.counter = authenticationInfo.newCounter;
            res.json({ verified: true, user: { id: user.id, username: user.username } });
        } else {
            res.status(400).json({ error: 'Could not verify authentication.' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    } finally {
        delete challenges[user.id];
    }
});

// --- 6. Start the server ---
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`DRONGO AUTONOMOUS server listening on port ${port}`);
});
