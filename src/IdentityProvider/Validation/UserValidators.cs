using FluentValidation;
using IdentityProvider.Models;

namespace IdentityProvider.Validation;

public class RegisterUserDtoValidator : AbstractValidator<RegisterUserDto>
{
    public RegisterUserDtoValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required")
            .EmailAddress().WithMessage("A valid email address is required");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required")
            .MinimumLength(6).WithMessage("Password must be at least 6 characters")
            .Matches("[A-Z]").WithMessage("Password must contain at least one uppercase letter")
            .Matches("[0-9]").WithMessage("Password must contain at least one number")
            .Matches("[^a-zA-Z0-9]").WithMessage("Password must contain at least one special character");

        RuleFor(x => x.PhoneNumber)
            .Matches(@"^\+?[0-9\s\-\(\)]+$").When(x => !string.IsNullOrEmpty(x.PhoneNumber))
            .WithMessage("Phone number format is invalid");

        RuleFor(x => x.Role)
            .Must(role => string.IsNullOrEmpty(role) ||
                          new[] { "Admin", "User" }.Contains(role))
            .WithMessage("Role must be either 'Admin', 'User', or empty");
    }
}

public class UpdateUserDtoValidator : AbstractValidator<UpdateUserDto>
{
    public UpdateUserDtoValidator()
    {
        RuleFor(x => x.Email)
            .EmailAddress().When(x => !string.IsNullOrEmpty(x.Email))
            .WithMessage("A valid email address is required");

        RuleFor(x => x.PhoneNumber)
            .Matches(@"^\+?[0-9\s\-\(\)]+$").When(x => !string.IsNullOrEmpty(x.PhoneNumber))
            .WithMessage("Phone number format is invalid");

        RuleFor(x => x.NewPassword)
            .MinimumLength(6).When(x => !string.IsNullOrEmpty(x.NewPassword))
            .WithMessage("Password must be at least 6 characters")
            .Matches("[A-Z]").When(x => !string.IsNullOrEmpty(x.NewPassword))
            .WithMessage("Password must contain at least one uppercase letter")
            .Matches("[0-9]").When(x => !string.IsNullOrEmpty(x.NewPassword))
            .WithMessage("Password must contain at least one number")
            .Matches("[^a-zA-Z0-9]").When(x => !string.IsNullOrEmpty(x.NewPassword))
            .WithMessage("Password must contain at least one special character");

        RuleFor(x => x.CurrentPassword)
            .NotEmpty().When(x => !string.IsNullOrEmpty(x.NewPassword))
            .WithMessage("Current password is required when setting a new password");
    }
}

public class ChangePasswordDtoValidator : AbstractValidator<ChangePasswordDto>
{
    public ChangePasswordDtoValidator()
    {
        RuleFor(x => x.CurrentPassword)
            .NotEmpty().WithMessage("Current password is required");

        RuleFor(x => x.NewPassword)
            .NotEmpty().WithMessage("New password is required")
            .MinimumLength(6).WithMessage("Password must be at least 6 characters")
            .Matches("[A-Z]").WithMessage("Password must contain at least one uppercase letter")
            .Matches("[0-9]").WithMessage("Password must contain at least one number")
            .Matches("[^a-zA-Z0-9]").WithMessage("Password must contain at least one special character")
            .NotEqual(x => x.CurrentPassword).WithMessage("New password cannot be the same as the current password");
    }
}

public class PaginationParamsValidator : AbstractValidator<PaginationParams>
{
    public PaginationParamsValidator()
    {
        RuleFor(x => x.Skip)
            .GreaterThanOrEqualTo(0).WithMessage("Skip must be greater than or equal to 0");

        RuleFor(x => x.Take)
            .InclusiveBetween(1, 100).WithMessage("Take must be between 1 and 100");
    }
}