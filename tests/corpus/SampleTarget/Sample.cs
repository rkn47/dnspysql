// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

[assembly: System.Reflection.AssemblyDescription("dnspysql test target")]

namespace Sample
{
    public interface IValidator
    {
        bool Validate(string code);
    }

    public enum Membership { Basic = 0, Plus = 1, Premium = 2 }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public sealed class FeatureAttribute : Attribute
    {
        public FeatureAttribute(string name) { Name = name; }
        public string Name { get; }
        public int Level { get; set; }
    }

    public struct Point { public int X; public int Y; public int Sum() => X + Y; }

    [Feature("cards", Level = 2)]
    public class MemberCard : IValidator
    {
        public const string Library = "CITY-LIBRARY";
        static readonly byte[] Table = { 1, 2, 3, 4, 5, 6, 7, 8 };
        private int checks;
        public Membership Membership { get; set; } = Membership.Basic;
        public event EventHandler Expired;

        public bool Validate(string code)
        {
            checks++;
            if (string.IsNullOrEmpty(code)) return false;
            return IsValid(code) && Checksum(code) % 7 == 3;
        }

        [Feature("core")]
        public virtual bool IsValid(string code)
        {
            try
            {
                return code.StartsWith("LIB-") && code.Length == 12;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        internal static int Checksum(string s)
        {
            int sum = 0;
            foreach (var c in s) sum = sum * 31 + c + Table[c % Table.Length];
            return Math.Abs(sum);
        }

        public int DaysLeft(DateTime now)
        {
            switch (Membership)
            {
                case Membership.Basic: return 14 - now.Day % 14;
                case Membership.Plus: return 365;
                default: return int.MaxValue;
            }
        }

        public void CheckExpiry(int days)
        {
            if (days <= 0) Expired?.Invoke(this, EventArgs.Empty);
        }

        public IEnumerable<string> Features()
        {
            yield return "basic";
            if (Membership >= Membership.Plus) yield return "plus";
        }

        public async Task<bool> ValidateAsync(string code)
        {
            await Task.Delay(1);
            return Validate(code);
        }

        public List<string> Filter(IEnumerable<string> codes, int min) => codes.Where(k => k.Length > min).Select(k => k.ToUpperInvariant()).ToList();

        public int Checks => checks;
    }

    public class GuestCard : MemberCard
    {
        public override bool IsValid(string code) => code == "GUEST";
        public override string ToString() => "Guest:" + base.ToString() + GetHashCode();
        public override int GetHashCode() => 7;
    }

    public static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetTickCount();

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);
    }

    public class Repository<T> where T : class
    {
        private readonly List<T> items = new List<T>();
        public void Add(T item) => items.Add(item);
        public T Find(Func<T, bool> pred) => items.FirstOrDefault(pred);
        public int Count => items.Count;
    }

    internal static class Strings
    {
        static readonly System.Resources.ResourceManager rm = new System.Resources.ResourceManager("SampleTarget.Strings", typeof(Strings).Assembly);
        public static string CardExpired => rm.GetString("CardExpired");
    }

    public static class Program
    {
        public static int Main(string[] args)
        {
            var card = new MemberCard();
            var ok = card.Validate(args.Length > 0 ? args[0] : "none");
            Console.WriteLine(ok ? "Accepted" : "Rejected: " + Strings.CardExpired);
            var repo = new Repository<string>();
            repo.Add("x");
            return ok ? 0 : 1;
        }
    }
}
