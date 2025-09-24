using FluentValidation;
using FluentValidation.Results;

namespace IdentityProvider.Validation;

public static class ValidationExtensions
{
    public static void AddFluentValidation(this IServiceCollection services)
    {
        services.AddValidatorsFromAssemblyContaining<Program>(ServiceLifetime.Singleton);
    }

    public static async Task<ValidationResult> ValidateAsync<T>(this IValidator<T> validator, T instance, HttpContext httpContext)
    {
        var validationResult = await validator.ValidateAsync(instance);

        httpContext.Items["ValidationResult"] = validationResult;

        return validationResult;
    }

    public static IDictionary<string, string[]> GetValidationErrorsDictionary(this ValidationResult validationResult)
    {
        return validationResult.Errors
            .GroupBy(e => e.PropertyName)
            .ToDictionary(
                g => g.Key,
                g => g.Select(e => e.ErrorMessage).ToArray()
            );
    }
}