using System.Security.Principal;

namespace ZeroTrace.Core.Util;

/// <summary>Determines whether the current process runs with administrative rights.</summary>
public static class PrivilegeChecker
{
    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}
