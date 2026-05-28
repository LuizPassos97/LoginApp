using Microsoft.AspNetCore.Hosting;

namespace LoginApp.Services;

public static class JwtSecretValidator
{
    public static void Validate(string secret, IWebHostEnvironment environment)
    {
        if (secret.Length < 32)
            throw new InvalidOperationException("Jwt:Secret must be at least 32 characters.");

        if (secret == "CHANGE_THIS_TO_A_SECURE_RANDOM_SECRET_AT_LEAST_32_CHARS")
            throw new InvalidOperationException("Jwt:Secret still uses the scaffold placeholder.");

        if (environment.IsProduction() && secret.Contains("DEV_ONLY", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Jwt:Secret must be supplied from production secret storage.");
    }
}
