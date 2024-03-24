import { parse, stringify } from 'smol-toml';
import { generateKeyPair, exportPKCS8, exportJWK, exportSPKI, importSPKI, calculateJwkThumbprint } from 'jose';
import fs from 'node:fs';

const generateJWKS = async (env) => {
	const publicKey = await importSPKI(env.publicJwtKey, 'RS256');
	const publicJwk = await exportJWK(publicKey);
	const publicJwkThumbprint = await calculateJwkThumbprint(publicJwk);
	const jwksObj = {
		keys: [
			{
				use: 'sig',
				kty: publicJwk.kty,
				n: publicJwk.n,
				e: publicJwk.e,
				kid: publicJwkThumbprint,
				alg: 'RS256',
				key_ops: ['verify'],
			},
		],
	};

	return jwksObj;
};

// Selected algorithm is RS256: RSASSA-PKCS1-v1_5 using SHA-256
// Public Key exported to SPKI format
// Private Key exported to PKCS8 format
const generateAndSaveNewJWT = async () => {
	const { publicKey, privateKey } = await generateKeyPair('RS256');

	const publicJwtKey = await exportSPKI(publicKey);
	const privateJwtKey = await exportPKCS8(privateKey);
	const wranglerTomlContents = fs.readFileSync(`./wrangler.toml`, 'utf8');
	const wranglerObj = parse(wranglerTomlContents);

	const publicJwk = await exportJWK(publicKey);
	const publicJwkThumbprint = await calculateJwkThumbprint(publicJwk);
	const jwksObj = {
		keys: [
			{
				use: 'sig',
				kty: publicJwk.kty,
				n: publicJwk.n,
				e: publicJwk.e,
				kid: publicJwkThumbprint,
				alg: 'RS256',
				key_ops: ['verify'],
			},
		],
	};

	const jwks = JSON.stringify(jwksObj);

	wranglerObj.vars = { publicJwtKey, privateJwtKey, jwks };

	const newToml = stringify(wranglerObj);

	fs.writeFileSync('./wrangler.toml', newToml);
};

generateAndSaveNewJWT();
