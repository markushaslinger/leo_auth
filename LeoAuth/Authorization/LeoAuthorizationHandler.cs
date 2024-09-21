using Microsoft.AspNetCore.Authorization;

namespace LeoAuth;

public sealed class LeoAuthorizationHandler : AuthorizationHandler<LeoAuthRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, LeoAuthRequirement requirement)
    {
        try
        {
            var leoUser = context.User.GetLeoUserInformation();
            leoUser.Switch(user => HandleUserAuth(user, context, requirement),
                           _ =>
                               context.Fail(new AuthorizationFailureReason(this,
                                                                           $"No {nameof(LeoUser)} data available")));
        } 
        catch (Exception e)
        {
            var message = $"Error while handling {nameof(LeoAuthRequirement)}: {e.Message}";
            context.Fail(new AuthorizationFailureReason(this, message));
        }

        return Task.CompletedTask;
    }

    private void HandleUserAuth(LeoUser user, AuthorizationHandlerContext context, LeoAuthRequirement requirement)
    {
        var success = requirement.RequiredRole switch
                {
                    LeoUserRole.Student
                        when !requirement.AllowHigherRole => user.Role is LeoUserRole.Student,
                    LeoUserRole.Student
                        when requirement.AllowHigherRole => user.Role is LeoUserRole.Student
                                                                         or LeoUserRole.Teacher,
                    LeoUserRole.Teacher => user.Role is LeoUserRole.Teacher,
                    _                   => false
                };
        if (success)
        {
            context.Succeed(requirement);
        }
        else
        {
            context.Fail(new AuthorizationFailureReason(this, "User does not have required role"));
        }
    }
}
