import { calculateJwkThumbprint, SignJWT, exportJWK, importPKCS8, importSPKI } from 'jose';

// Selected algorithm is RS256: RSASSA-PKCS1-v1_5 using SHA-256
// Public Key is in SPKI format
// Private Key is in PKCS8 format
const generateJWKS = async (env) => {
	const publicKey = await importSPKI(env.publicJwtKey, 'RS256');
	console.log(publicKey);
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

const generateToken = async (env) => {
	const privateKey = await importPKCS8(env.privateJwtKey, 'RS256');

	const token = await new SignJWT({
		verified: true,
	})
		.setProtectedHeader({
			typ: 'JWT',
			alg: 'RS256',
		})
		.setIssuer('syncosaurus')
		.setSubject('verified')
		.setAudience('valid syncosaurus app users')
		.setExpirationTime('6h')
		.setIssuedAt()
		.sign(privateKey);

	return token;
};

export { generateJWKS, generateToken };
