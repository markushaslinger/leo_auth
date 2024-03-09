using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OneOf;
using OneOf.Types;

namespace LeoAuth.Server;

public class PersistingRevalidatingLeoAuthenticationStateProvider
    : RevalidatingServerAuthenticationStateProvider
{
    private readonly ILogger _logger;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly PersistentComponentState _state;
    private readonly PersistingComponentStateSubscription _subscription;
    private readonly bool _throwIfPersistingFails;

    private Task<AuthenticationState>? _authenticationStateTask;

    public PersistingRevalidatingLeoAuthenticationStateProvider(
        ILoggerFactory loggerFactory,
        IServiceScopeFactory scopeFactory,
        PersistentComponentState state,
        bool throwIfPersistingFails = false)
        : base(loggerFactory)
    {
        _scopeFactory = scopeFactory;
        _state = state;
        _logger = loggerFactory.CreateLogger<PersistingRevalidatingLeoAuthenticationStateProvider>();
        _throwIfPersistingFails = throwIfPersistingFails;

        AuthenticationStateChanged += OnAuthenticationStateChanged;
        _subscription = state.RegisterOnPersisting(OnPersistingAsync, RenderMode.InteractiveWebAssembly);
    }

    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState, CancellationToken cancellationToken)
    {
        // Get the user manager from a new scope to ensure it fetches fresh data
        await using var scope = _scopeFactory.CreateAsyncScope();

        return ValidateSecurityStampAsync(authenticationState.User);
    }

    private static bool ValidateSecurityStampAsync(IPrincipal principal) =>
        principal.Identity?.IsAuthenticated is not false;

    private void OnAuthenticationStateChanged(Task<AuthenticationState> authenticationStateTask)
    {
        _authenticationStateTask = authenticationStateTask;
    }

    private async Task OnPersistingAsync()
    {
        if (_authenticationStateTask is null)
        {
            throw new
                LeoAuthException($"Authentication state not set in {nameof(PersistingRevalidatingLeoAuthenticationStateProvider)}.{nameof(OnPersistingAsync)}().");
        }

        var authenticationState = await _authenticationStateTask;
        var principal = authenticationState.User;

        OneOf<LeoUser, None> leoUser;
        if (principal.Identity?.IsAuthenticated == true && principal.Identity is ClaimsIdentity identity)
        {
            leoUser = LeoUserProvider.ExtractLeoUserInformation(identity);
        }
        else
        {
            leoUser = new None();
        }

        leoUser.Switch(user =>
                       {
                           var serializableUser = SerializableLeoUserWithClaims.FromLeoUser(user);
                           _state.PersistAsJson(nameof(SerializableLeoUserWithClaims), serializableUser);
                       },
                       _ =>
                       {
                           const string PersistingErrorMessage
                               = "No user information found in the authentication state, could not persist";
                           _logger.LogWarning(PersistingErrorMessage);
                           if (_throwIfPersistingFails)
                           {
                               throw new LeoAuthException(PersistingErrorMessage);
                           }
                       });
    }

    protected override void Dispose(bool disposing)
    {
        _subscription.Dispose();
        AuthenticationStateChanged -= OnAuthenticationStateChanged;
        base.Dispose(disposing);
    }
}
