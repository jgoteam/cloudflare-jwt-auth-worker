import { jwtVerify, createRemoteJWKSet, errors } from 'jose';

const getJWT = (request) => {
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer')) {
		return null;
	}

	return authHeader.substring(6).trim();
};

const verifyRequestAuthToken = async (token, jwksURL) => {
	// const token = getJWT(request);

	if (!token) {
		return new Response('Request is missing a required authentication token', { status: 400, statusText: "Bad Request" });
	}

	const jwks = createRemoteJWKSet(new URL(jwksURL));
	let verificationResult;
	try {
		verificationResult = await jwtVerify(token, jwks);
		return Response.json(verificationResult);
	} catch (error) {
		if (error instanceof errors.JWSSignatureVerificationFailed || error instanceof errors.JWTInvalid) {
			return new Response('Error: Provided authorization token is invalid', { status: 401, statusText: "Unauthorized", headers: {
				"WWW-Authenticate": `Bearer realm=${request.url}`
			} });
		} else if (err instanceof errors.JWTExpired) {
			return new Response('Error: Token is expired', { status: 401, statusText: "Unauthorized" });
		} else {
			return new Response('Error: Unknown Authentication Error. Access Denied.', { status: 401, statusText: "Unauthorized" });
		}
	}
};

export { verifyRequestAuthToken };
