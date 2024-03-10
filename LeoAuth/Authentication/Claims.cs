using System.Security.Claims;

namespace LeoAuth;

internal static class Claims
{
    public const string UserNameClaimType = "preferred_username";
    public const string LdapEntryClaimType = "LDAP_ENTRY_DN";
    public const string LastNameClaimType = ClaimTypes.Surname; 
    public const string FirstNameClaimType = ClaimTypes.GivenName; 
    
}
