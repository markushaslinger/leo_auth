using System.Collections.Frozen;

namespace LeoAuth;

public readonly record struct Department(DepartmentType Type, string Name)
{
    internal static readonly FrozenDictionary<DepartmentType, string> DepartmentNames = new Dictionary<DepartmentType, string>
    {
        [DepartmentType.Unset] = "Unknown",
        [DepartmentType.AD] = "Abendschule",
        [DepartmentType.BG] = "Biomedizin- und Gesundheitstechnik",
        [DepartmentType.FE] = "Fachschule Elektronik",
        [DepartmentType.HE] = "Höhere Elektronik",
        [DepartmentType.IF] = "Informatik",
        [DepartmentType.IT] = "Medientechnik"
    }.ToFrozenDictionary();
}

public enum DepartmentType
{
    Unset = 0,
    AD = 5,
    BG = 10,
    FE = 15,
    HE = 20,
    IF = 25,
    IT = 30,
    KD = 35
}
