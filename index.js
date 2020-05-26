async function authorize(options) {

  validateAuthOptions(options);

  const pkceCodeVerifier = generateRandomString();
  localStorage.setItem('pkceCodeVerifier', pkceCodeVerifier);
  const pkceCodeChallenge = await pkceChallengeFromVerifier(pkceCodeVerifier);

  let authUrl = options.driveUri + '?pauth-method=authorize'
    + `&response_type=code`
    + `&client_id=${encodeURIComponent(window.location.origin)}`
    + `&redirect_uri=${encodeURIComponent(window.location.href)}`
    + `&code_challenge=${encodeURIComponent(pkceCodeChallenge)}`
    + `&code_challenge_method=S256`;

  if (options.perms) {
    const scope = encodeScopeFromPerms(options.perms);
    authUrl += `&scope=${encodeURIComponent(scope)}`;
  }

  const stateCode = generateRandomString();
  localStorage.setItem('oauthState', stateCode);

  localStorage.setItem('remfsAuthDriveUri', options.driveUri);

  if (options.state) {
    authUrl += `&state=${encodeURIComponent(stateCode + options.state)}`;
  }
  else {
    authUrl += `&state=${encodeURIComponent(stateCode)}`;
  }

  window.location.href = authUrl;
}

async function completeAuthorization(options) {

  const urlParams = new URLSearchParams(window.location.search);

  const code = urlParams.get('code');
  urlParams.delete('code');

  const savedState = localStorage.getItem('oauthState');
  localStorage.removeItem('oauthState');

  const returnedState = urlParams.get('state');

  if (savedState !== returnedState.slice(0, savedState.length)) {
    alert("Invalid state returned from authorization server. Aborting");
    // go back to app home
    window.location = window.location.origin + window.location.pathname;
  }

  const driveUri = localStorage.getItem('remfsAuthDriveUri');
  localStorage.removeItem('remfsAuthDriveUri');

  const state = returnedState.slice(savedState.length);
  urlParams.delete('state');

  const redirParamsStr = decodeURIComponent(urlParams.toString()); 

  if (redirParamsStr !== '') {
    history.pushState(null, '', window.location.pathname + '?' + redirParamsStr);
  }
  else {
    history.pushState(null, '', window.location.pathname);
  }

  const codeVerifier = localStorage.getItem('pkceCodeVerifier');
  localStorage.removeItem('pkceCodeVerifier');

  const tokenUrl = driveUri + `?pauth-method=token`
  const params = `grant_type=authorization_code`
    + `&client_id=${encodeURIComponent(window.location.origin)}`
    + `&redirect_uri=${encodeURIComponent(window.location.href)}`
    + `&code=${code}`
    + `&code_verifier=${codeVerifier}`;

  const accessToken = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    },
    body: params,
  })
  .then(r => r.json())
  .then(json => json.access_token);

  return {
    state,
    accessToken,
  };
}

function validateAuthOptions(options) {
  if (!options) {
    throw new Error("Must provide options object");
  }

  const required = [
    'driveUri',
  ];

  for (const req of required) {
    if (!options[req]) {
      throw new Error("Missing " + req);
    }
  }
}

function encodeScopeFromPerms(perms) {
  let scope = '';

  for (const permParams of perms) {

    scope += `type=${permParams.type};perm=${permParams.perm}`;

    if (permParams.path) {
      const path = permParams.path;
      const trimmedPath = path.length > 1 && path.endsWith('/') ? path.slice(0, path.length - 1) : path;
      scope += `;path=${trimmedPath.replace(/ /g, '[]')}`;
    }

    scope += ' ';
  }

  // remove trailing space
  return scope.slice(0, scope.length - 1);
}

// The following functions were taken from:
// https://github.com/aaronpk/pkce-vanilla-js

// Generate a secure random string using the browser crypto functions
function generateRandomString() {
  const array = new Uint32Array(28);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
}

// Calculate the SHA256 hash of the input text. 
// Returns a promise that resolves to an ArrayBuffer
function sha256(plain) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return window.crypto.subtle.digest('SHA-256', data);
}

// Base64-urlencodes the input string
function base64urlencode(str) {
  // Convert the ArrayBuffer to string using Uint8 array to conver to what btoa accepts.
  // btoa accepts chars only within ascii 0-255 and base64 encodes them.
  // Then convert the base64 encoded to base64url encoded
  //   (replace + with -, replace / with _, trim trailing =)
  return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Return the base64-urlencoded sha256 hash for the PKCE challenge
async function pkceChallengeFromVerifier(v) {
  const hashed = await sha256(v);
  return base64urlencode(hashed);
}


export {
  authorize,
  completeAuthorization,
};
