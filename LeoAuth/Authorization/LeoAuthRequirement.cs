using Microsoft.AspNetCore.Authorization;

namespace LeoAuth;

public readonly struct LeoAuthRequirement(LeoUserRole requiredRole, bool allowHigherRole) : IAuthorizationRequirement
{
    public LeoUserRole RequiredRole { get; } = requiredRole;
    public bool AllowHigherRole { get; } = allowHigherRole;
}
