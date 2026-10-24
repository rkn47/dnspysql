// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql;

// The interpreter's memory: a copy of the module image that pointers read and write (anti-tamper code), and the
// scratch memory of localloc.
public sealed partial class Emulator
{
    // The image anti-tamper code reads and decrypts through pointers: a copy of the file at a made-up base address.
    // FullyQualifiedName says "<Unknown>" (loaded from bytes), so the code uses the file layout, which is this copy.
    const long ImageBase = 0x10000000;
    byte[]? _image;
    LoadedModule? _imageOf;

    /// <summary>The image after the code that ran changed it, or null if nothing asked for it.</summary>
    public byte[]? Image => _image;

    byte[] ImageOf(LoadedModule m)
    {
        if (_image == null) { _image = (byte[])(m.FileBytes ?? m.OriginalBytes).Clone(); _imageOf = m; }
        else if (_imageOf != m) throw new Failed("pointers into a second module's image");
        return _image;
    }

    // localloc (stackalloc): memory of its own at addresses far from the image's, zeroed as .locals init has it. Nothing
    // is freed within a call; the next call starts it over.
    const long ScratchBase = 0x70000000;
    const int MaxScratch = 16 << 20;
    byte[] _scratch = [];
    int _scratchUsed;

    long Localloc(long n)
    {
        if (n < 0 || n > MaxScratch - _scratchUsed) throw new Failed($"localloc of {n} bytes (more than {MaxScratch >> 20} MB in one call)");
        int at = (_scratchUsed + 7) & ~7, end = (int)Math.Min(at + n, MaxScratch);
        if (end > _scratch.Length) Array.Resize(ref _scratch, Math.Min(MaxScratch, Math.Max(end, _scratch.Length * 2)));
        Array.Clear(_scratch, at, end - at); // used before, by an earlier call
        _scratchUsed = end;
        return ScratchBase + at;
    }

    // The bytes a pointer addresses: in the scratch memory, or in the module image.
    (byte[] Buffer, int Offset) At(object? address, int size)
    {
        long a = address switch { long l => l, int i => (uint)i, _ => throw new Failed($"pointer access through a {Describe(address)}") };
        if (a >= ScratchBase && a - ScratchBase <= _scratchUsed - size) return (_scratch, (int)(a - ScratchBase));
        long off = a - ImageBase;
        if (_image == null || off < 0 || off + size > _image.Length) throw new Failed($"pointer 0x{a:X} outside the module image");
        return (_image, (int)off);
    }

    Span<byte> Bytes(object? address, int size)
    {
        var (buffer, offset) = At(address, size);
        if (buffer == _image) _written += size;
        return buffer.AsSpan(offset, size);
    }

    object Read(Code op, object? address)
    {
        int size = op switch { Code.Ldind_I1 or Code.Ldind_U1 => 1, Code.Ldind_I2 or Code.Ldind_U2 => 2, Code.Ldind_I8 or Code.Ldind_I or Code.Ldind_R8 => 8, _ => 4 };
        var (buffer, offset) = At(address, size);
        var span = buffer.AsSpan(offset, size);
        // each arm boxed as itself: a switch expression would otherwise widen them all to double
        return op switch
        {
            Code.Ldind_I1 => (object)(int)(sbyte)span[0], Code.Ldind_U1 => (object)(int)span[0],
            Code.Ldind_I2 => (object)(int)BitConverter.ToInt16(span), Code.Ldind_U2 => (object)(int)BitConverter.ToUInt16(span),
            Code.Ldind_I8 or Code.Ldind_I => (object)BitConverter.ToInt64(span), Code.Ldind_R4 => (object)(double)BitConverter.ToSingle(span),
            Code.Ldind_R8 => (object)BitConverter.ToDouble(span),
            Code.Ldind_I4 or Code.Ldind_U4 => (object)BitConverter.ToInt32(span),
            _ => throw new Failed($"{op} through a pointer"),
        };
    }

    long _written; // bytes stored into the image (not the scratch memory)

    void Write(Code op, object? address, object? v)
    {
        int size = op switch { Code.Stind_I1 => 1, Code.Stind_I2 => 2, Code.Stind_I8 or Code.Stind_I or Code.Stind_R8 => 8, _ => 4 };
        var span = Bytes(address, size);
        long l = v switch { int i => i, long x => x, double d => (long)d, _ => throw new Failed($"{op} of a {Describe(v)}") };
        switch (size)
        {
            case 1: span[0] = (byte)l; break;
            case 2: BitConverter.TryWriteBytes(span, (short)l); break;
            case 4: if (op == Code.Stind_R4) BitConverter.TryWriteBytes(span, (float)Num(v)); else BitConverter.TryWriteBytes(span, (int)l); break;
            default: if (op == Code.Stind_R8) BitConverter.TryWriteBytes(span, Num(v)); else BitConverter.TryWriteBytes(span, l); break;
        }
    }
}
