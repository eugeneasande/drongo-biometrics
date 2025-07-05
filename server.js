// =================================================================
// DRONGO AUTONOMOUS - WEBAUTHN BACKEND SERVER (CORS fixed)
// =================================================================

const express = require('express');
const cors = require('cors');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(express.json());

// --- CORS FIX ---
// ✅ Replaces the previous dynamic origin checker
app.use(cors({
  origin: 'https://eugeneasande.github.io', // Your frontend
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));

// --- In-Memory Store (temporary unless using JSON later) ---
const users = {};
const challenges = {};

// --- WebAuthn Config ---
const rpName = 'DRONGO AUTONOMOUS';
const rpID = 'drongo-auth-server.onrender.com'; // Render domain
const origin = `https://${rpID}`;

// --- Registration Endpoint ---
app.post('/generate-registration-options', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  if (!users[username]) {
    users[username] = {
      id: `user_${Date.now()}`,
      username,
      authenticators: []
    };
  }

  const user = users[username];

  const options = generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.id,
    userName: user.username,
    attestationType: 'none',
    excludeCredentials: user.authenticators.map(auth => ({
      id: auth.credentialID,
      type: 'public-key',
      transports: auth.transports,
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
      response,
      expectedChallenge,
      expectedOrigin: 'https://eugeneasande.github.io', // ✅ Must match frontend
      expectedRPID: rpID,
    });

    const { verified, registrationInfo } = verification;
    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;
      user.authenticators.push({
        credentialID,
        credentialPublicKey,
        counter,
        transports: response.response.transports || [],
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

// --- Authentication Endpoint ---
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
      response,
      expectedChallenge,
      expectedOrigin: 'https://eugeneasande.github.io', // ✅ Must match frontend
      expectedRPID: rpID,
      authenticator,
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

// --- Server Start ---
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`DRONGO AUTONOMOUS server running on port ${port}`);
});
