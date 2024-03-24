import { generateToken } from './authorize.js';
import { verifyRequestAuthToken } from './verify.js';

export default {
	// /authorize path to generate new tokens
	// /verify path to verify tokens for access to CF DO
	// /jwks path to expose public key set

	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const jwksURL = `${url.protocol}//${url.host}/jwks`;

		switch (url.pathname) {
			case '/authorize':
				const token = await generateToken(env);
				return Response.json(token);
			case '/verify':
				return await verifyRequestAuthToken(request, jwksURL);
			case '/jwks':
				return new Response(env.jwks);
			default:
				return new Response(`Page not found: ${url.href}`, { status: 404 });
		}
	},
};
