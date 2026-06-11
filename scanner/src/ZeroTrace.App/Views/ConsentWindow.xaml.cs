using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace ZeroTrace.App.Views;

public partial class ConsentWindow : Window
{
    /// <summary>The 6-digit PIN the scan will be associated with.</summary>
    public string EnteredPin { get; private set; } = "";

    private TextBox[] _boxes = Array.Empty<TextBox>();
    private bool _locked;   // true when a PIN was embedded in the download

    public ConsentWindow()
    {
        InitializeComponent();
        _boxes = new[] { P0, P1, P2, P3, P4, P5 };
        TryLoadEmbeddedPin();
        UpdateState();
    }

    private static bool ValidPin(string? s) => Regex.IsMatch(s ?? "", @"^\d{6}$");

    private string CollectPin() => string.Concat(_boxes.Select(b => b.Text));

    private void UpdateState()
    {
        var pin = CollectPin();
        AcceptBtn.IsEnabled = ValidPin(pin);
        if (!_locked)
            PinHint.Text = pin.Length == 6 ? "PIN vollstaendig" : "Gib deinen 6-stelligen PIN ein";
    }

    // The website can bake a PIN into the download: either as a command-line
    // argument (--pin=123456) or in a "zerotrace.pin" file next to the exe.
    private void TryLoadEmbeddedPin()
    {
        try
        {
            string? pin = null;
            foreach (var a in Environment.GetCommandLineArgs())
                if (a.StartsWith("--pin=", StringComparison.OrdinalIgnoreCase))
                    pin = a.Substring("--pin=".Length);

            if (pin is null)
            {
                var file = Path.Combine(AppContext.BaseDirectory, "zerotrace.pin");
                if (File.Exists(file)) pin = File.ReadAllText(file).Trim();
            }

            pin = (pin ?? "").Trim();
            if (!ValidPin(pin)) return;

            for (int i = 0; i < _boxes.Length; i++)
            {
                _boxes[i].Text = pin[i].ToString();
                _boxes[i].IsReadOnly = true;
            }
            _locked = true;
            PinHint.Text = "PIN aus Download";
        }
        catch
        {
            // Ignore embedded-PIN problems; the user can still type one in.
        }
    }

    private void Pin_GotFocus(object sender, RoutedEventArgs e)
    {
        if (sender is TextBox tb) tb.SelectAll();
    }

    private void Pin_Changed(object sender, TextChangedEventArgs e)
    {
        if (sender is not TextBox tb) return;

        // Keep digits only.
        var digits = new string(tb.Text.Where(char.IsDigit).ToArray());
        if (tb.Text != digits)
        {
            tb.Text = digits;
            tb.CaretIndex = tb.Text.Length;
        }

        // Advance to the next box once a digit is entered.
        if (tb.Text.Length == 1)
        {
            int i = Array.IndexOf(_boxes, tb);
            if (i >= 0 && i < _boxes.Length - 1) _boxes[i + 1].Focus();
        }

        UpdateState();
    }

    private void Pin_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Back || sender is not TextBox tb) return;
        if (tb.Text.Length == 0)
        {
            int i = Array.IndexOf(_boxes, tb);
            if (i > 0)
            {
                _boxes[i - 1].Focus();
                if (!_boxes[i - 1].IsReadOnly) _boxes[i - 1].Text = "";
                e.Handled = true;
            }
        }
    }

    private void Accept_Click(object sender, RoutedEventArgs e)
    {
        var pin = CollectPin();
        if (!ValidPin(pin))
        {
            PinHint.Text = "Bitte den 6-stelligen PIN eingeben";
            return;
        }
        EnteredPin = pin;
        DialogResult = true;
        Close();
    }

    private void Decline_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
