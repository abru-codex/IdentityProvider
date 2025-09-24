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
        var rsa = RSA.Create();
        _rsaKey = new RsaSecurityKey(rsa);

        _keyId = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString()));
        _rsaKey.KeyId = _keyId;
    }

    public SigningCredentials GetSigningCredentials()
    {
        return new SigningCredentials(_rsaKey, SecurityAlgorithms.RsaSha256);
    }

    public SecurityKey GetSecurityKey()
    {
        return _rsaKey;
    }

    public IList<JsonWebKey> GetJsonWebKeys()
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(_rsaKey);
        jwk.Alg = SecurityAlgorithms.RsaSha256;
        jwk.Use = "sig";
        jwk.Kid = _keyId;

        return new List<JsonWebKey> { jwk };
    }
}