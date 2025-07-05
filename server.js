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
const allowedOrigins = [
    'https://drongo-login.onrender.com', // Replace with your actual front-end URL on Render
    'http://127.0.0.1:5500', // For local development
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
// In a real-world application, this data would be stored securely in a
// PostgreSQL database on Render. For this example, we'll store it in memory.
const users = {}; // { username: { id, username, authenticators } }
const challenges = {}; // { userId: challenge }

// --- 4. WebAuthn Configuration ---
const rpName = 'DRONGO AUTONOMOUS';
// The rpID should be the domain of your front-end, WITHOUT the protocol.
const rpID = 'drongo-login.onrender.com'; // Example: your-app-name.onrender.com
// The origin is the full URL where your front-end is hosted.
const origin = `https://${rpID}`;

// =================================================================
// --- 5. API Endpoints ---
// =================================================================

// A. REGISTRATION ENDPOINTS

/**
 * 1. Generate Registration Options
 * Called by the front-end when a user wants to register a new device.
 */
app.post('/generate-registration-options', (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }

    // Create a new user if they don't exist. In a real app, you'd check your DB.
    if (!users[username]) {
        users[username] = {
            id: `user_${Date.now()}`,
            username,
            authenticators: [],
        };
    }

    const user = users[username];

    const options = generateRegistrationOptions({
        rpName,
        rpID,
        userID: user.id,
        userName: user.username,
        attestationType: 'none',
        // Exclude authenticators that have already been registered by this user
        excludeCredentials: user.authenticators.map(auth => ({
            id: auth.credentialID,
            type: 'public-key',
            transports: auth.transports,
        })),
    });

    // Store the challenge to verify it later
    challenges[user.id] = options.challenge;

    console.log(`Generated registration options for ${username}`);
    res.json(options);
});

/**
 * 2. Verify Registration
 * Called by the front-end after the user has approved the registration
 * with their fingerprint/authenticator.
 */
app.post('/verify-registration', async (req, res) => {
    const { username, response } = req.body;
    const user = users[username];

    if (!user || !challenges[user.id]) {
        return res.status(400).json({ error: 'User or challenge not found.' });
    }

    const expectedChallenge = challenges[user.id];

    try {
        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });

        const { verified, registrationInfo } = verification;

        if (verified && registrationInfo) {
            const { credentialPublicKey, credentialID, counter } = registrationInfo;

            // Save the new authenticator to the user's record (in memory)
            users[username].authenticators.push({
                credentialID,
                credentialPublicKey,
                counter,
                transports: response.response.transports || [],
            });

            console.log(`Successfully registered authenticator for ${username}`);
            res.json({ verified: true });
        } else {
            res.status(400).json({ error: 'Could not verify registration.' });
        }
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ error: error.message });
    } finally {
        delete challenges[user.id]; // Clean up the challenge
    }
});

// B. AUTHENTICATION (LOGIN) ENDPOINTS

/**
 * 3. Generate Authentication Options
 * Called by the front-end when a user wants to log in.
 */
app.post('/generate-authentication-options', (req, res) => {
    const { username } = req.body;
    const user = users[username];

    if (!user || user.authenticators.length === 0) {
        return res.status(400).json({ error: 'User not found or has no registered authenticators.' });
    }

    const options = generateAuthenticationOptions({
        allowCredentials: user.authenticators.map(auth => ({
            id: auth.credentialID,
            type: 'public-key',
            transports: auth.transports,
        })),
        userVerification: 'preferred',
    });

    // Store challenge to verify later
    challenges[user.id] = options.challenge;

    console.log(`Generated authentication options for ${username}`);
    res.json(options);
});

/**
 * 4. Verify Authentication
 * Called by the front-end after the user has approved the login with their fingerprint.
 */
app.post('/verify-authentication', async (req, res) => {
    const { username, response } = req.body;
    const user = users[username];

    if (!user || !challenges[user.id]) {
        return res.status(400).json({ error: 'User or challenge not found.' });
    }

    const expectedChallenge = challenges[user.id];
    const authenticator = user.authenticators.find(
        auth => auth.credentialID.toString() === response.id
    );

    if (!authenticator) {
        return res.status(400).json({ error: 'Authenticator not recognized.' });
    }

    try {
        const verification = await verifyAuthenticationResponse({
            response,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            authenticator,
        });

        const { verified, authenticationInfo } = verification;

        if (verified) {
            // Update the authenticator's counter
            authenticator.counter = authenticationInfo.newCounter;
            console.log(`Successfully authenticated ${username}`);
            res.json({ verified: true, user: { id: user.id, username: user.username } });
        } else {
            res.status(400).json({ error: 'Could not verify authentication.' });
        }
    } catch (error) {
        console.error('Authentication verification error:', error);
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
