// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Runtime.InteropServices;

namespace Sample;

// A small library app: member cards, shapes for the reading-room floor plan, defaults, a dice game.
public static class Program
{
    public static int Main(string[] args)
    {
        var card = new MemberCard("LIB-1234");
        Console.WriteLine(card.IsValid() ? "accepted" : "not accepted");
        Console.WriteLine(Native.GetTickCount() > 0 ? "tick" : "no tick");
        Console.WriteLine(new Box<int>(42).Value);
        return card.IsValid() ? 0 : 3;
    }
}

// A library card number: a fixed prefix and a checksum over its characters.
[Obsolete("demo attribute")]
public sealed class MemberCard(string number)
{
    const string Prefix = "LIB-";

    public string Number { get; } = number;

    public bool IsValid() => Number.StartsWith(Prefix) && Checksum(Number) == 0x2A;

    static int Checksum(string s)
    {
        int sum = 0;
        foreach (var c in s) sum = (sum * 31 + c) & 0xFF;
        return sum;
    }

    public event EventHandler? Expired;

    internal void Expire() => Expired?.Invoke(this, EventArgs.Empty);

    public sealed class Nested
    {
        public static readonly int[] Table = [1, 2, 3, 4, 5, 6, 7, 8];
    }
}

public struct Box<T>(T value)
{
    public T Value = value;
}

internal static class Native
{
    [DllImport("kernel32.dll")]
    public static extern uint GetTickCount();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "MessageBoxW")]
    public static extern int ShowMessage(IntPtr hwnd, string text, string caption, uint type);
}

public interface IShape { double Area(); }

// Virtual dispatch for the analyzer relations (method.virtual_used_by, event.overrides).
public abstract class Shape : IShape
{
    public abstract double Area();
    public virtual string Describe() => "shape";
    public virtual event EventHandler? Changed;
    protected void OnChanged() => Changed?.Invoke(this, EventArgs.Empty);
}

public sealed class Square(double side) : Shape
{
    public override double Area() => side * side;
    public override string Describe() => "square, a " + base.Describe(); // a non-virtual call of the base slot
    public override event EventHandler? Changed;
}

public static class Shapes
{
    public static double Total(IShape s) => s.Area();     // through the interface slot
    public static string Name(Shape s) => s.Describe();   // through the base slot
    public static double Direct(Square s) => s.Area();    // direct
}

public enum Color { Red, Green = 5, Blue }

// An async method: its body moves to a state machine's MoveNext, which the call graph links back to it.
public static class Async
{
    public static async Task<int> Compute(int x)
    {
        await Task.Delay(1);
        return Twice(x);
    }

    static int Twice(int x) => x * 2;
}

// The values the app starts with, stored by the static constructor (field_inits).
public static class Defaults
{
    public static string Title = "City Library";
    public static int MaxLoans = 5;
    public static bool Reminders = true;
    public static string[] Branches = ["North", "South"];
    public static byte[] Pattern = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    public static string Motto = "";
}

public static class Dice
{
    public static int Roll() => new Random().Next(1, 7);
}

public static class Greeter
{
    public static void Say(string name) => Console.WriteLine("Hello, " + name);
}
