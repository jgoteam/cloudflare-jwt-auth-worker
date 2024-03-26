import { generateToken } from './authorize.js';
import { verifyRequestAuthToken } from './verify.js';

const allowedOrigin = '*';

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
				const generatedToken = await generateToken(env);
				return Response.json(generatedToken, corsHeaders);
			case '/verify':
				const queriedToken = new URL(request.url).searchParams.get('token') ?? "";
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
