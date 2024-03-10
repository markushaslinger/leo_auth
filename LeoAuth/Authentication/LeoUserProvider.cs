using System.Collections.Frozen;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Components.Authorization;
using OneOf;
using OneOf.Types;
using DepartmentStruct = LeoAuth.Department;

namespace LeoAuth;

public static class LeoUserProvider
{
    private static readonly HashSet<string> relevantClaimTypes =
    [
        Claims.UserNameClaimType,
        Claims.LdapEntryClaimType,
        Claims.LastNameClaimType,
        Claims.FirstNameClaimType
    ];

    public static OneOf<LeoUser, None> ExtractLeoUserInformation(ClaimsIdentity identity)
    {
        var claims = identity.Claims;
        var relevantClaims = claims
                             .Select(c => (Claim: c, Type: c.Type.Trim()))
                             .Where(t => relevantClaimTypes.Contains(t.Type))
                             .ToDictionary(t => t.Type, t => t.Claim);

        if (relevantClaims.Count == 0)
        {
            return new None();
        }

        var name = ExtractName(relevantClaims.GetValueOrDefault(Claims.LastNameClaimType),
                               relevantClaims.GetValueOrDefault(Claims.FirstNameClaimType));
        var ldapInformation = new LdapInformation(GetLdapEntries(),
                                                  relevantClaims.GetValueOrDefault(Claims.UserNameClaimType));

        return LeoUser.FromLdapInformation(ldapInformation.Username, ldapInformation.OrganizationalUnits,
                                           name, ldapInformation.Department);

        IReadOnlyCollection<LdapEntry> GetLdapEntries()
        {
            IReadOnlyCollection<LdapEntry>? ldapEntries = null;
            if (relevantClaims.TryGetValue(Claims.LdapEntryClaimType, out var ldapEntryDnClaim))
            {
                ldapEntries = ExtractLdapEntries(ldapEntryDnClaim);
            }
            
            return ldapEntries ?? [];
        }
    }

    public static async ValueTask<OneOf<LeoUser, None>> GetLeoUserInformation(
        this AuthenticationStateProvider authenticationStateProvider)
    {
        var state = await authenticationStateProvider.GetAuthenticationStateAsync();

        return GetLeoUserInformation(state.User.Identity);
    }

    public static OneOf<LeoUser, None> GetLeoUserInformation(this ClaimsPrincipal user) =>
        GetLeoUserInformation(user.Identity);

    private static OneOf<LeoUser, None> GetLeoUserInformation(IIdentity? identity) =>
        identity is not ClaimsIdentity claimsIdentity
            ? new None()
            : ExtractLeoUserInformation(claimsIdentity);

    private static LeoUserName ExtractName(Claim? lastNameClaim, Claim? firstNameClaim)
    {
        var isLastNameValid = IsValid(lastNameClaim?.Value, out var lastName);
        var isFirstNameValid = IsValid(firstNameClaim?.Value, out var firstName);

        if (isLastNameValid && isFirstNameValid)
        {
            return new FullName(firstName, lastName);
        }

        if (isLastNameValid && !isFirstNameValid)
        {
            return new LastNameOnly(lastName);
        }

        if (!isLastNameValid && isFirstNameValid)
        {
            return new FirstNameOnly(firstName);
        }

        return new None();

        static bool IsValid(string? value, out string safeValue)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                safeValue = string.Empty;

                return false;
            }

            safeValue = value.Trim();

            return true;
        }
    }

    private static List<LdapEntry> ExtractLdapEntries(Claim ldapClaim)
    {
        var value = ldapClaim.Value.Trim();
        var entries = value.Split(',');
        var ldapEntries = entries.Select(e => e.Split('='))
                                 .Where(a => a.Length == 2 && a.All(s => !string.IsNullOrWhiteSpace(s)))
                                 .Select(a => (Key: a[0].Trim().ToLowerInvariant(), Value: a[1].Trim()))
                                 .Select(t =>
                                 {
                                     var key = t.Key switch
                                               {
                                                   "cn" => LdapEntryType.CommonName,
                                                   "ou" => LdapEntryType.OrganizationalUnit,
                                                   "dc" => LdapEntryType.DomainController,
                                                   _    => LdapEntryType.Unknown
                                               };

                                     return new LdapEntry(key, t.Value);
                                 }).ToList();

        return ldapEntries;
    }

    private sealed class LdapInformation
    {
        private static readonly FrozenDictionary<string, DepartmentType> departmentMapping =
            Enum.GetValues<DepartmentType>()
                .ToFrozenDictionary(v => v.ToString().ToLowerInvariant(),
                                    v => v);

        public LdapInformation(IReadOnlyCollection<LdapEntry> entries, Claim? userNameClaim)
        {
            OrganizationalUnits = entries.Where(e => e.Type == LdapEntryType.OrganizationalUnit)
                                         .Select(e => e.Value)
                                         .ToList();
            Username = DetermineUsername(userNameClaim, entries);
            Department = DetermineDepartment(entries);
        }

        public IReadOnlyCollection<string> OrganizationalUnits { get; }
        public OneOf<string, None> Username { get; }
        public OneOf<DepartmentStruct, None> Department { get; }

        private static OneOf<string, None> DetermineUsername(Claim? userNameClaim, IEnumerable<LdapEntry> entries)
        {
            if (userNameClaim is not null)
            {
                return userNameClaim.Value;
            }

            var commonNameClaim = entries.FirstOrDefault(e => e.Type == LdapEntryType.CommonName);

            return commonNameClaim != default(LdapEntry)
                ? commonNameClaim.Value
                : new None();
        }

        private static OneOf<DepartmentStruct, None> DetermineDepartment(IEnumerable<LdapEntry> entries)
        {
            var possibleDepartments = entries
                                      .Where(e => e.Type == LdapEntryType.OrganizationalUnit)
                                      .Select(e => e.Value.ToLowerInvariant())
                                      .Where(v => !string.IsNullOrWhiteSpace(v));
            foreach (var possibleDepartment in possibleDepartments)
            {
                if (departmentMapping.TryGetValue(possibleDepartment, out var departmentType))
                {
                    if (!DepartmentStruct.DepartmentNames.TryGetValue(departmentType, out var name))
                    {
                        name = DepartmentStruct.DepartmentNames[DepartmentType.Unset];
                    }

                    return new DepartmentStruct(departmentType, name);
                }
            }

            return new None();
        }
    }

    private sealed record LdapEntry(LdapEntryType Type, string Value);

    private enum LdapEntryType
    {
        Unknown = 0,
        CommonName = 1,
        OrganizationalUnit = 2,
        DomainController = 3
    }
}
