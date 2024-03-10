using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;

namespace LeoAuth;

public class PersistentLeoAuthenticationStateProvider(PersistentComponentState persistentState)
    : AuthenticationStateProvider
{
    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (!persistentState.TryTakeFromJson<SerializableLeoUserWithClaims>(nameof(SerializableLeoUserWithClaims), out var userInfo)
            || userInfo is null)
        {
            return Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));
        }

        var restoredClaims = userInfo.GetRestoredClaims();

        var claims = restoredClaims
            .Select(rc => new Claim(rc.ClaimType, rc.Value));

        var claimsIdentity = new ClaimsIdentity(claims, nameof(PersistentLeoAuthenticationStateProvider));
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
        var authenticationState = new AuthenticationState(claimsPrincipal);

        return Task.FromResult(authenticationState);
    }
}
