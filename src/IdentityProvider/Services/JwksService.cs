using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.Services;

public class JwksService
{
    private readonly RsaSecurityKey _rsaKey;
    private readonly string _keyId;

    public JwksService()
    {
        // Generate a new RSA key pair
        var rsa = RSA.Create();
        _rsaKey = new RsaSecurityKey(rsa);

        // Generate a key ID (kid) for the key
        _keyId = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString()));
        _rsaKey.KeyId = _keyId;
    }

    // Get the signing credentials for JWT tokens
    public SigningCredentials GetSigningCredentials()
    {
        return new SigningCredentials(_rsaKey, SecurityAlgorithms.RsaSha256);
    }

    // Get the security key for token validation
    public SecurityKey GetSecurityKey()
    {
        return _rsaKey;
    }

    // Get the JSON Web Key Set (JWKS) for the public key
    public IList<JsonWebKey> GetJsonWebKeys()
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(_rsaKey);
        jwk.Alg = SecurityAlgorithms.RsaSha256;
        jwk.Use = "sig";
        jwk.Kid = _keyId;

        return new List<JsonWebKey> { jwk };
    }
}