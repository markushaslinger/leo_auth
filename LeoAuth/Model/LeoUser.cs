using System.Collections.Frozen;
using System.Diagnostics;
using OneOf;
using OneOf.Types;

namespace LeoAuth;

[DebuggerDisplay("{DebuggerDisplay}")]
public sealed class LeoUser
{
    private readonly FrozenSet<string> _organizationalUnits;
    private bool? _isStudent;
    private bool? _isTeacher;
    private bool? _isTestUser;

    private LeoUser(OneOf<string, None> username, IEnumerable<string> organizationalUnits,
                    LeoUserName name, OneOf<Department, None> department)
    {
        _organizationalUnits = organizationalUnits
                               .Select(ou => ou.ToLowerInvariant())
                               .ToFrozenSet();
        Username = username;
        Name = name;
        Department = department;
    }

    public OneOf<string, None> Username { get; }
    public LeoUserName Name { get; }
    public OneOf<Department, None> Department { get; }
    public IEnumerable<string> OrganizationalUnits => _organizationalUnits;
    public bool IsTeacher => _isTeacher ??= _organizationalUnits.Contains("teachers");
    public bool IsStudent => _isStudent ??= _organizationalUnits.Contains("students");
    public bool IsTestUser => _isTestUser ??= _organizationalUnits.Contains("testusers");

    public LeoUserRole Role =>
        IsStudent || IsTestUser
            ? LeoUserRole.Student
            : IsTeacher
                ? LeoUserRole.Teacher
                : LeoUserRole.Unknown;

    private string DebuggerDisplay
    {
        get
        {
            var name = Username.Match(name => name,
                                      _ => Name.Match<OneOf<string, None>>(fullName => fullName.Name,
                                                                           firstNameOnly => firstNameOnly.FirstName,
                                                                           lastNameOnly => lastNameOnly.LastName,
                                                                           _ => new None()))
                               .Match(name => $"{name}, ",
                                      _ => string.Empty);
            var department = Department.Match(department => $"{department.ToString()}, ",
                                              _ => string.Empty);
            var type = IsStudent
                ? "Student"
                : IsTeacher
                    ? "Teacher"
                    : IsTestUser
                        ? "TestUser"
                        : string.Empty;

            return $"{name}{department}{type}";
        }
    }

    public bool IsPartOfClass(string className) => _organizationalUnits.Contains(className.ToLowerInvariant());

    internal static LeoUser FromLdapInformation(OneOf<string, None> username,
                                                IEnumerable<string> organizationalUnits,
                                                LeoUserName name, OneOf<Department, None> department) =>
        new(username, organizationalUnits, name, department);
}
