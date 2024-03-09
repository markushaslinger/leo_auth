using OneOf;
using OneOf.Types;

namespace LeoAuth;

public readonly record struct FullName(string FirstName, string LastName)
{
    public string Name => $"{FirstName} {LastName}";
}
public readonly record struct FirstNameOnly(string FirstName);
public readonly record struct LastNameOnly(string LastName);

[GenerateOneOf]
public sealed partial class LeoUserName : OneOfBase<FullName, FirstNameOnly, LastNameOnly, None>
{
    private const char Separator = ';';
    
    internal string Serialize() =>
        Match(
              name => $"{name.FirstName}{Separator}{name.LastName}",
              firstName => $"{firstName.FirstName}{Separator}",
              lastName => $"{Separator}{lastName.LastName}",
              _ => $"{Separator}"
             );

    internal static LeoUserName Deserialize(string serialized)
    {
        var parts = serialized.Split(Separator);
        if (parts.Length != 2)
        {
            return new None();
        }
        
        var (firstName, lastName) = (parts[0], parts[1]);
        var hasFirstName = !string.IsNullOrWhiteSpace(firstName);
        var hasLastName = !string.IsNullOrWhiteSpace(lastName);
        
        if (hasFirstName && hasLastName)
        {
            return new FullName(firstName, lastName);
        }
        
        if (hasFirstName && !hasLastName)
        {
            return new FirstNameOnly(firstName);
        }
        
        if (!hasFirstName && hasLastName)
        {
            return new LastNameOnly(lastName);
        }
        
        return new None();
    }
}