namespace LeoAuth;

internal sealed class SerializableLeoUserWithClaims
{
    public required string Username { get; set; }
    public required List<string> OrganizationalUnits { get; set; }
    public required string Name { get; set; }

    public static SerializableLeoUserWithClaims FromLeoUser(LeoUser user) =>
        new()
        {
            Username = user.Username.Match(name => name,
                                           _ => string.Empty),
            OrganizationalUnits = user.OrganizationalUnits.ToList(),
            Name = user.Name.Serialize()
        };

    public IEnumerable<RestoredClaim> GetRestoredClaims()
    {
        List<RestoredClaim> restoredClaims =
        [
            new RestoredClaim(Claims.LdapEntryClaimType, CreateLdapClaimValue()),
            .. CreateNameClaims()
        ];

        if (Username != string.Empty)
        {
            restoredClaims.Add(new RestoredClaim(Claims.UserNameClaimType, Username));
        }

        return restoredClaims;

        string CreateLdapClaimValue()
        {
            IEnumerable<string> fixDomainComponents = ["EDU", "HTL-LEONDING", "AC", "AT"];
            var domainComponents = fixDomainComponents.Select(dc => $"DC={dc}");
            var organizationalUnits = OrganizationalUnits.Select(ou => $"OU={ou}");
            var commonName = $"CN={Username}";
            var ldapEntries = string.Join(",", [commonName, .. organizationalUnits, ..domainComponents]);

            return ldapEntries;
        }

        IEnumerable<RestoredClaim> CreateNameClaims()
        {
            var name = LeoUserName.Deserialize(Name);

            return name.Match<IEnumerable<RestoredClaim>>(fullName =>
                                                          [
                                                              new RestoredClaim(Claims.FirstNameClaimType,
                                                                                fullName.FirstName),
                                                              new RestoredClaim(Claims.LastNameClaimType,
                                                                                fullName.LastName)
                                                          ],
                                                          firstNameOnly =>
                                                          [
                                                              new RestoredClaim(Claims.FirstNameClaimType,
                                                                                firstNameOnly.FirstName)
                                                          ],
                                                          lastNameOnly =>
                                                          [
                                                              new RestoredClaim(Claims.LastNameClaimType,
                                                                                lastNameOnly.LastName)
                                                          ],
                                                          _ => []);
        }
    }

    internal readonly record struct RestoredClaim(string ClaimType, string Value);
}
