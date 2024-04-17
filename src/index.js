import { generateToken } from './authorize.js';
import { verifyRequestAuthToken } from './verify.js';

// This is a sample Cloudflare JWT Auth Worker template, and is for demonstration purposes only.
// It clearly does not follow security best practices.
const allowedOrigin = '*';

// Instead of a simple in-memory object, valid credentials should be hashed and stored in a secure DB
const validCredentials = {
	foobar: 'cats',
};

export default {
	// /authorize path to generate new tokens
	// /verify path to verify tokens
	// /jwks path to expose public key set

	async fetch(request, env, ctx) {
		if (request.method === 'OPTIONS') {
			return new Response(null, {
				status: 204,
				headers: {
					'Access-Control-Allow-Credentials': 'true',
					'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
					'Access-Control-Allow-Origin': allowedOrigin,
					'Access-Control-Allow-Headers': 'Content-Type',
				},
			});
		}

		const url = new URL(request.url);
		const jwksURL = `${url.protocol}//${url.host}/jwks`;
		const corsHeaders = {
			headers: {
				'Access-Control-Allow-Origin': allowedOrigin,
				'Access-Control-Allow-Credentials': 'true',
			},
		};

		switch (url.pathname) {
			case '/authorize':
				const requestHeaders = await request.headers;
				const jsonHeader = requestHeaders.get('content-type') === 'application/json';

				if (requestHeaders && jsonHeader) {
					const { username, password } = await request.json();

					if (validCredentials[username] === password) {
						console.log('valid password');
						const generatedToken = await generateToken(env);
						return Response.json(generatedToken, corsHeaders);
					} else {
						return new Response('Missing or Invalid Credentials Provided', { status: 401, statusText: 'Unauthorized' });
					}
				} else {
					return new Response('Missing or Invalid Credentials Provided', { status: 401, statusText: 'Unauthorized' });
				}

			case '/verify':
				const queriedToken = new URL(request.url).searchParams.get('token') ?? '';
				let response = await verifyRequestAuthToken(queriedToken, jwksURL);
				response.headers.set('Access-Control-Allow-Origin', allowedOrigin);
				response.headers.set('Access-Control-Allow-Credentials', 'true');

				return response;
			case '/jwks':
				return new Response(env.jwks, corsHeaders);
			default:
				return new Response(`Page not found: ${url.href}`, { status: 404, headers: corsHeaders.headers });
		}
	},
};
