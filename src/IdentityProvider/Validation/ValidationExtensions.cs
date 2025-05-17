using FluentValidation;
using FluentValidation.Results;

namespace IdentityProvider.Validation;

public static class ValidationExtensions
{
    public static void AddFluentValidation(this IServiceCollection services)
    {
        // Register all validators from the assembly
        services.AddValidatorsFromAssemblyContaining<Program>(ServiceLifetime.Singleton);
    }

    // Extension method for validation in minimal APIs
    public static async Task<ValidationResult> ValidateAsync<T>(this IValidator<T> validator, T instance, HttpContext httpContext)
    {
        var validationResult = await validator.ValidateAsync(instance);

        // Add validation errors to HttpContext items for potential middleware handling
        httpContext.Items["ValidationResult"] = validationResult;

        return validationResult;
    }

    // Extension method to get errors dictionary for Results.ValidationProblem
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