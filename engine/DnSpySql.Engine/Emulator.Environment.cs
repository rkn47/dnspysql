// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using dnlib.DotNet;

namespace DnSpySql;

// What the code may ask of the machine it runs on, answered without asking it: one entry per API, so the policy is one
// list (and the emulator_model table). Machine-specific values are placeholders (%TEMP%\, %USERNAME%), so a plaintext
// says where a path would go instead of naming the analyst's machine; anti-debug checks get the answers of a process
// without a debugger; what only takes time or sets up a UI does nothing; what would end the process or wait for a
// thread stops the interpretation with the reason.
public sealed partial class Emulator
{
    /// <summary>One thing the code may ask of its environment and what it gets here.</summary>
    /// <param name="Kind">placeholder | no debugger | image | no-op | refused</param>
    public sealed record EnvironmentEntry(string Api, string Kind, string Answer, string Why);

    delegate bool Answer(Emulator e, MethodDef caller, object? self, object?[] a, out object? result);
    sealed record Entry(EnvironmentEntry Doc, Answer Run);

    static Entry Value(string api, string kind, object? value, string why) =>
        new(new(api, kind, value is string s ? $"\"{s.Replace("\r", "\\r").Replace("\n", "\\n")}\"" : Convert.ToString(value) ?? "null", why),
            (Emulator _, MethodDef _, object? _, object?[] _, out object? r) => { r = value; return true; });

    static Entry Rule(string api, string kind, string answer, string why, Answer run) => new(new(api, kind, answer, why), run);

    // what a call that only passes time or sets up the UI returns: nothing, and nothing changes
    static readonly Answer Nothing = (Emulator _, MethodDef _, object? _, object?[] _, out object? r) => { r = null; return true; };

    static Answer On<T>(Func<T, object?[], object?> answer) where T : class =>
        (Emulator _, MethodDef _, object? self, object?[] a, out object? r) =>
        {
            r = self is T t ? answer(t, a) : null;
            return self is T;
        };

    static string? Text(object?[] a, int i) => i < a.Length ? (a[i] is Ref r ? r.Get() : a[i]) as string : null;

    static readonly Entry[] ManagedEntries =
    [
        // ---- placeholders ----
        Value("System.String System.Environment::get_UserName()", "placeholder", "%USERNAME%", "machine-specific"),
        Value("System.String System.Environment::get_MachineName()", "placeholder", "%COMPUTERNAME%", "machine-specific"),
        Value("System.String System.Environment::get_UserDomainName()", "placeholder", "%USERDOMAIN%", "machine-specific"),
        Value("System.String System.Environment::get_SystemDirectory()", "placeholder", @"%SystemRoot%\system32", "machine-specific"),
        Value("System.String System.IO.Path::GetTempPath()", "placeholder", @"%TEMP%\", "machine-specific"),
        Value("System.String System.IO.Path::GetTempFileName()", "placeholder", @"%TEMP%\tmp0000.tmp", "the file is not created"),
        Value("System.String System.Environment::get_NewLine()", "placeholder", "\r\n", "Windows'"),
        Rule("System.String System.Environment::GetEnvironmentVariable(System.String)", "placeholder", "%NAME%", "the variable's name, not its value",
            (Emulator _, MethodDef _, object? _, object?[] a, out object? r) => { r = $"%{Text(a, 0)}%"; return true; }),
        Rule("System.String System.Environment::GetFolderPath(System.Environment/SpecialFolder)", "placeholder", "%Folder%", "the folder's name",
            (Emulator _, MethodDef _, object? _, object?[] a, out object? r) =>
            { r = $"%{Enum.GetName(typeof(Environment.SpecialFolder), (int)AsLong(a[0])) ?? "folder " + a[0]}%"; return true; }),
        Rule("System.String System.Reflection.Assembly::get_Location()", "placeholder", @"%APPDIR%\<file>", "where the sample's own assembly would be",
            On<AsmStub>((s, _) => $@"%APPDIR%\{System.IO.Path.GetFileName(s.M.Path)}")),
        Value("System.String System.Windows.Forms.Application::get_StartupPath()", "placeholder", "%APPDIR%", "where the program would be"),
        Rule("System.String System.Windows.Forms.Application::get_ExecutablePath()", "placeholder", @"%APPDIR%\<file>", "where the program would be",
            (Emulator e, MethodDef caller, object? _, object?[] _, out object? r) =>
            { r = $@"%APPDIR%\{System.IO.Path.GetFileName(e.ModuleOf(caller.Module)?.Path ?? "app.exe")}"; return true; }),
        Value("System.String Microsoft.VisualBasic.Interaction::Command()", "placeholder", "", "the command line: started without arguments"),
        Value("System.Diagnostics.Process System.Diagnostics.Process::GetCurrentProcess()", "placeholder", "a process", "a pseudo handle and an id, nothing else")
            with { Run = (Emulator _, MethodDef _, object? _, object?[] _, out object? r) => { r = new ProcessStub(); return true; } },
        Rule("System.IntPtr System.Diagnostics.Process::get_Handle()", "placeholder", "-1", "the current-process pseudo handle", On<ProcessStub>((_, _) => -1L)),
        Rule("System.Int32 System.Diagnostics.Process::get_Id()", "placeholder", "4242", "machine-specific", On<ProcessStub>((_, _) => 4242)),

        // ---- anti-debug: a process without a debugger ----
        Value("System.Boolean System.Diagnostics.Debugger::get_IsAttached()", "no debugger", 0, "no debugger is attached"),
        Value("System.Boolean System.Diagnostics.Debugger::IsLogging()", "no debugger", 0, "no debugger is attached"),

        // ---- time, threads, locks and the UI: one thread here, nothing waits, nothing is drawn ----
        Rule("System.Void System.Threading.Thread::Sleep(System.Int32)", "no-op", "returns at once", "sleeping changes no data", Nothing),
        Rule("System.Void System.Threading.Thread::Sleep(System.TimeSpan)", "no-op", "returns at once", "sleeping changes no data", Nothing),
        Rule("System.Void System.Threading.Monitor::Enter(System.Object)", "no-op", "the lock is free", "one thread", Nothing),
        Rule("System.Void System.Threading.Monitor::Exit(System.Object)", "no-op", "", "one thread", Nothing),
        Rule("System.Void System.Threading.Monitor::Enter(System.Object,System.Boolean&)", "no-op", "the lock is free (taken = true)", "one thread",
            (Emulator _, MethodDef _, object? _, object?[] a, out object? r) => { r = null; if (a.Length == 2 && a[1] is Ref taken) taken.Set(1); return true; }),
        Rule("System.Void System.Threading.Thread::.ctor(System.Threading.ThreadStart)", "no-op", "a thread", "created, its code is not run",
            (Emulator _, MethodDef _, object? _, object?[] a, out object? r) => { r = new ThreadStub(a[0]); return true; }),
        Rule("System.Void System.Threading.Thread::.ctor(System.Threading.ParameterizedThreadStart)", "no-op", "a thread", "created, its code is not run",
            (Emulator _, MethodDef _, object? _, object?[] a, out object? r) => { r = new ThreadStub(a[0]); return true; }),
        Rule("System.Void System.Threading.Thread::Start()", "no-op", "", "started threads are usually watchdogs; their code is not run", On<ThreadStub>((_, _) => null)),
        Rule("System.Void System.Threading.Thread::Start(System.Object)", "no-op", "", "started threads are usually watchdogs; their code is not run", On<ThreadStub>((_, _) => null)),
        Rule("System.Void System.Threading.Thread::set_IsBackground(System.Boolean)", "no-op", "", "a thread's setting", On<ThreadStub>((_, _) => null)),
        Rule("System.Void System.Threading.Thread::set_Priority(System.Threading.ThreadPriority)", "no-op", "", "a thread's setting", On<ThreadStub>((_, _) => null)),
        Rule("System.Void System.Threading.Thread::set_Name(System.String)", "no-op", "", "a thread's setting", On<ThreadStub>((_, _) => null)),
        Value("System.AppDomain System.AppDomain::get_CurrentDomain()", "no-op", "the domain", "for its resolve events")
            with { Run = (Emulator _, MethodDef _, object? _, object?[] _, out object? r) => { r = new AppDomainStub(); return true; } },
        Rule("System.Void System.AppDomain::add_AssemblyResolve(System.ResolveEventHandler)", "no-op", "", "assemblies the code loads are found by name", On<AppDomainStub>((_, _) => null)),
        Rule("System.Void System.AppDomain::add_ResourceResolve(System.ResolveEventHandler)", "no-op", "", "assemblies the code loads are found by name", On<AppDomainStub>((_, _) => null)),
        Rule("System.Void System.AppDomain::add_TypeResolve(System.ResolveEventHandler)", "no-op", "", "assemblies the code loads are found by name", On<AppDomainStub>((_, _) => null)),
        Rule("System.Void System.Windows.Forms.Application::EnableVisualStyles()", "no-op", "", "UI setup: nothing is drawn", Nothing),
        Rule("System.Void System.Windows.Forms.Application::SetCompatibleTextRenderingDefault(System.Boolean)", "no-op", "", "UI setup: nothing is drawn", Nothing),

        // ---- what cannot be answered ----
        Rule("System.Void System.Threading.Thread::Join()", "refused", "stops", "the code waits for a thread's result, and a started thread's code is not run",
            (Emulator _, MethodDef _, object? self, object?[] _, out object? r) =>
            { r = null; return self is ThreadStub ? throw new Failed("Thread.Join: the code waits for a thread's result, and a started thread's code is not run here") : false; }),
        Rule("System.Boolean System.Threading.Thread::Join(System.Int32)", "refused", "stops", "the code waits for a thread's result, and a started thread's code is not run",
            (Emulator _, MethodDef _, object? self, object?[] _, out object? r) =>
            { r = null; return self is ThreadStub ? throw new Failed("Thread.Join: the code waits for a thread's result, and a started thread's code is not run here") : false; }),
        Rule("System.Void System.Environment::FailFast(System.String)", "refused", "stops", "the code would end the process",
            (Emulator _, MethodDef _, object? _, object?[] _, out object? r) => throw new Failed("the code would end the process here (FailFast)")),
        Rule("System.Void System.Environment::Exit(System.Int32)", "refused", "stops", "the code would end the process",
            (Emulator _, MethodDef _, object? _, object?[] _, out object? r) => throw new Failed("the code would end the process here (Exit)")),
    ];

    // P/Invokes, by entry point
    static readonly Entry[] NativeEntries =
    [
        // the image copy is writable already; the old protection is what Windows reports for a loaded image's code
        Rule("VirtualProtect", "image", "1 (old protection 0x20, execute-read)", "the image copy is writable already",
            (Emulator _, MethodDef _, object? _, object?[] a, out object? r) => { if (a.Length == 4 && a[3] is Ref old) old.Set(0x20); r = 1; return true; }),
        Value("IsDebuggerPresent", "no debugger", 0, "no debugger is attached"),
        Rule("CheckRemoteDebuggerPresent", "no debugger", "1 (present = false)", "no debugger is attached",
            (Emulator _, MethodDef _, object? _, object?[] a, out object? r) => { if (a.Length == 2 && a[1] is Ref present) present.Set(0); r = 1; return true; }),
    ];

    static readonly Dictionary<string, Entry> Managed = ManagedEntries.ToDictionary(e => e.Doc.Api, StringComparer.Ordinal);
    static readonly Dictionary<string, Entry> Native = NativeEntries.ToDictionary(e => e.Doc.Api, StringComparer.Ordinal);

    // Calls whose result differs on every run: refused, since a plaintext from them would be one of many.
    static readonly (string Match, string What)[] NondeterministicCalls =
    [
        (" System.Random::", "random numbers"), (" System.Security.Cryptography.RandomNumberGenerator::", "random numbers"),
        (" System.Guid::NewGuid(", "a new GUID"), (" System.DateTime::get_Now(", "the time"), (" System.DateTime::get_UtcNow(", "the time"),
        (" System.Environment::get_TickCount", "the time since boot"), (" System.Diagnostics.Stopwatch::", "elapsed time"),
    ];

    static bool Nondeterministic(string full) => NondeterministicCalls.Any(n => full.Contains(n.Match, StringComparison.Ordinal));

    bool AnsweredManaged(string full, MethodDef caller, object? self, object?[] a, out object? result)
    {
        result = null;
        return Managed.TryGetValue(full, out var e) && e.Run(this, caller, self, a, out result);
    }

    bool AnsweredNative(string entryPoint, MethodDef caller, object?[] a, out object? result)
    {
        result = null;
        return Native.TryGetValue(entryPoint, out var e) && e.Run(this, caller, null, a, out result);
    }

    /// <summary>
    /// The interpreter's model of the world, for the emulator_model table: the environment answers, the framework types
    /// and members it calls, the members it refuses, and the calls refused because their result differs on every run.
    /// </summary>
    public static IEnumerable<(string Area, string Name, string Kind, string Answer, string Why)> Model()
    {
        foreach (var e in ManagedEntries) yield return ("environment", e.Doc.Api, e.Doc.Kind, e.Doc.Answer, e.Doc.Why);
        foreach (var e in NativeEntries) yield return ("environment", "P/Invoke " + e.Doc.Api, e.Doc.Kind, e.Doc.Answer, e.Doc.Why);
        foreach (var (match, what) in NondeterministicCalls)
            yield return ("nondeterministic", match.Trim(), "refused", "stops", $"{what}: the result differs on every run");
        foreach (var name in Allowed.Keys.Order(StringComparer.Ordinal))
            yield return ("allowlist", name, "allowed type", "called", "computes on data in memory");
        foreach (var (type, (_, members)) in Partly)
            foreach (var m in members.Order(StringComparer.Ordinal))
                yield return ("allowlist", $"{type}::{m}", "allowed member", "called", "only these members of the type");
        foreach (var b in Blocked) yield return ("allowlist", b, "blocked member", "stops", "hands out something outside the allowlist or touches the environment");
    }
}
