using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using ZeroTrace.Core.Models;

namespace ZeroTrace.App.Converters;

/// <summary>Maps a RiskLevel to a brush for pills/badges.</summary>
public sealed class RiskLevelToBrushConverter : IValueConverter
{
    public static readonly SolidColorBrush Low = New("#3B82F6");
    public static readonly SolidColorBrush Medium = New("#F59E0B");
    public static readonly SolidColorBrush High = New("#F97316");
    public static readonly SolidColorBrush Critical = New("#EF4444");

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is RiskLevel r ? r switch
        {
            RiskLevel.Critical => Critical,
            RiskLevel.High => High,
            RiskLevel.Medium => Medium,
            _ => Low
        } : Low;

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) =>
        throw new NotSupportedException();

    private static SolidColorBrush New(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }
}

/// <summary>bool -> Visibility (true = Visible). Pass "invert" to flip.</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool b = value is bool v && v;
        if (parameter is string s && s.Equals("invert", StringComparison.OrdinalIgnoreCase)) b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) =>
        value is Visibility vis && vis == Visibility.Visible;
}

/// <summary>null/empty -> Collapsed, otherwise Visible.</summary>
public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool has = value is not null && !(value is string s && string.IsNullOrEmpty(s));
        return has ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) =>
        throw new NotSupportedException();
}

/// <summary>Formats a byte count compactly.</summary>
public sealed class BytesToHumanConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is null) return "0 B";
        double bytes = System.Convert.ToDouble(value);
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        int u = 0;
        while (bytes >= 1024 && u < units.Length - 1) { bytes /= 1024; u++; }
        return $"{bytes:0.#} {units[u]}";
    }

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) =>
        throw new NotSupportedException();
}

/// <summary>Returns true when bound value equals the parameter (nav highlight / radio enums).</summary>
public sealed class EqualsToBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value?.ToString() == parameter?.ToString();

    public object ConvertBack(object? value, Type t, object? parameter, CultureInfo c) =>
        value is bool b && b && parameter is not null ? parameter : Binding.DoNothing;
}
