using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;

namespace ZeroTrace.App.Views;

/// <summary>
/// Lightweight animated "particle network" background that mirrors the HTML
/// demo: faintly glowing dots drift around and are joined by thin lines when
/// they come close. Pure WPF — drawn in <see cref="OnRender"/> and ticked via
/// <see cref="CompositionTarget.Rendering"/>. Cheap enough for ~26 particles.
/// </summary>
public sealed class ParticleField : FrameworkElement
{
    private struct Particle
    {
        public double X, Y, VX, VY, R, A, DA;
        public int Dir;
    }

    private readonly List<Particle> _particles = new();
    private readonly Random _rng = new();
    private bool _running;
    private bool _seeded;

    public ParticleField()
    {
        Loaded += (_, _) => Start();
        Unloaded += (_, _) => Stop();
        SizeChanged += (_, _) => Seed();
    }

    private void Start()
    {
        if (_running) return;
        _running = true;
        CompositionTarget.Rendering += OnTick;
    }

    private void Stop()
    {
        if (!_running) return;
        _running = false;
        CompositionTarget.Rendering -= OnTick;
    }

    private void Seed()
    {
        double w = ActualWidth, h = ActualHeight;
        if (w <= 0 || h <= 0) return;

        _particles.Clear();
        for (int i = 0; i < 26; i++)
        {
            _particles.Add(new Particle
            {
                X = _rng.NextDouble() * w,
                Y = _rng.NextDouble() * h,
                VX = (_rng.NextDouble() - 0.5) * 0.4,
                VY = (_rng.NextDouble() - 0.5) * 0.4,
                R = 1 + _rng.NextDouble() * 2,
                A = _rng.NextDouble(),
                DA = 0.005 + _rng.NextDouble() * 0.008,
                Dir = _rng.NextDouble() > 0.5 ? 1 : -1
            });
        }
        _seeded = true;
    }

    private void OnTick(object? sender, EventArgs e)
    {
        if (!_seeded) Seed();
        double w = ActualWidth, h = ActualHeight;
        if (w <= 0 || h <= 0) return;

        for (int i = 0; i < _particles.Count; i++)
        {
            var p = _particles[i];
            p.A += p.DA * p.Dir;
            if (p.A > 0.45 || p.A < 0.05) p.Dir *= -1;
            p.X += p.VX;
            p.Y += p.VY;
            if (p.X < 0 || p.X > w) p.VX *= -1;
            if (p.Y < 0 || p.Y > h) p.VY *= -1;
            _particles[i] = p;
        }
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w <= 0 || h <= 0 || _particles.Count == 0) return;

        // Faint connecting lines between nearby particles.
        for (int i = 0; i < _particles.Count; i++)
        {
            for (int j = i + 1; j < _particles.Count; j++)
            {
                double dx = _particles[i].X - _particles[j].X;
                double dy = _particles[i].Y - _particles[j].Y;
                double d = Math.Sqrt(dx * dx + dy * dy);
                if (d >= 82) continue;

                double alpha = (1 - d / 82) * 0.08;
                var pen = new Pen(
                    new SolidColorBrush(Color.FromArgb((byte)(alpha * 255), 0x4E, 0xBC, 0xD2)), 0.8);
                pen.Freeze();
                dc.DrawLine(pen,
                    new Point(_particles[i].X, _particles[i].Y),
                    new Point(_particles[j].X, _particles[j].Y));
            }
        }

        // The glowing dots.
        foreach (var p in _particles)
        {
            var b = new SolidColorBrush(Color.FromArgb((byte)(p.A * 255), 0x4E, 0xBC, 0xD2));
            b.Freeze();
            dc.DrawEllipse(b, null, new Point(p.X, p.Y), p.R, p.R);
        }
    }
}
