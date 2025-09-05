using FluentValidation;
using IdentityProvider.Models;

namespace IdentityProvider.Validation;

public class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty().WithMessage("Username is required")
            .EmailAddress().WithMessage("Username must be a valid email address");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required")
            .MinimumLength(6).WithMessage("Password must be at least 6 characters");
    }
}

public class OAuth2RequestValidator : AbstractValidator<OAuth2Request>
{
    public OAuth2RequestValidator()
    {
        RuleFor(x => x.ClientId)
            .NotEmpty().WithMessage("client_id is required");

        RuleFor(x => x.RedirectUri)
            .NotEmpty().WithMessage("redirect_uri is required");

        RuleFor(x => x.ResponseType)
            .NotEmpty().WithMessage("response_type is required")
            .Must(rt => rt == "code" || rt == "token" || rt == "id_token" ||
                  rt == "id_token token" || rt == "code id_token" ||
                  rt == "code token" || rt == "code id_token token")
            .WithMessage("Invalid response_type");

        RuleFor(x => x.Scope)
            .NotEmpty().WithMessage("scope is required");

        When(x => x.ResponseType.Contains("code") && !string.IsNullOrEmpty(x.CodeChallenge), () =>
        {
            RuleFor(x => x.CodeChallengeMethod)
                .Must(method => method == "plain" || method == "S256")
                .WithMessage("code_challenge_method must be 'plain' or 'S256'");
        });
    }
}

public class TokenRequestValidator : AbstractValidator<TokenRequest>
{
    public TokenRequestValidator()
    {
        RuleFor(x => x.GrantType)
            .NotEmpty().WithMessage("grant_type is required")
            .Must(gt => gt == "authorization_code" || gt == "refresh_token" ||
                  gt == "client_credentials" || gt == "password")
            .WithMessage("Invalid grant_type");

        RuleFor(x => x.ClientId)
            .NotEmpty().WithMessage("client_id is required");

        When(x => x.GrantType == "authorization_code", () =>
        {
            RuleFor(x => x.Code)
                .NotEmpty().WithMessage("code is required for authorization_code grant");

            RuleFor(x => x.RedirectUri)
                .NotEmpty().WithMessage("redirect_uri is required for authorization_code grant");
        });

        When(x => x.GrantType == "refresh_token", () =>
        {
            RuleFor(x => x.RefreshToken)
                .NotEmpty().WithMessage("refresh_token is required for refresh_token grant");
        });
    }
}