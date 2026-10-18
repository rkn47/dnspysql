// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
namespace DnSpySql;

/// <summary>
/// An LZMA decoder (the algorithm of Igor Pavlov's public-domain LZMA SDK) for the SDK's "alone" layout, which .NET
/// code embedding the SDK writes: 5 property bytes, the uncompressed size as 8 little-endian bytes, then the stream.
/// The interpreter decodes such a stream natively instead of interpreting the sample's own copy of the decoder, which
/// behind control-flow obfuscation can take hundreds of millions of IL instructions. Strict: a stream that does not decode to
/// exactly its declared size is rejected, so arbitrary bytes are not mistaken for LZMA.
/// </summary>
public static class Lzma
{
    const int MaxOutput = 256 << 20;

    /// <summary>
    /// The decompressed bytes of an LZMA "alone" blob, or null when it is not one. The size follows the properties as
    /// 8 bytes (the SDK's layout) or 4 (a variant some embedders write).
    /// </summary>
    public static byte[]? TryDecode(byte[] data)
    {
        if (data.Length < 13 || data[0] >= 9 * 5 * 5 || BitConverter.ToUInt32(data, 1) > 1u << 30) return null;
        return Try(data, BitConverter.ToInt64(data, 5), 13) ?? Try(data, BitConverter.ToUInt32(data, 5), 9);
    }

    static byte[]? Try(byte[] data, long size, int start)
    {
        if (size <= 0 || size > MaxOutput) return null;
        try
        {
            var output = new byte[size];
            return Decoder.Run(data, start, data[0], output) ? output : null;
        }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentException or InvalidDataException) { return null; }
    }

    sealed class Decoder
    {
        const int NumStates = 12, PosStatesMax = 16, AlignBits = 4, EndPosModelIndex = 14, FullDistances = 128, LenToPosStates = 4;
        const int MatchMinLen = 2, LowBits = 3, MidBits = 3, HighBits = 8;

        // range decoder
        readonly byte[] _in;
        int _pos;
        uint _range = 0xFFFFFFFF, _code;

        // probabilities, 11 bits each
        readonly ushort[] _isMatch = new ushort[NumStates << 4], _isRep = new ushort[NumStates], _isRepG0 = new ushort[NumStates],
            _isRepG1 = new ushort[NumStates], _isRepG2 = new ushort[NumStates], _isRep0Long = new ushort[NumStates << 4],
            _posDecoders = new ushort[FullDistances - EndPosModelIndex], _align = new ushort[1 << AlignBits];
        readonly ushort[][] _posSlot = new ushort[LenToPosStates][];
        readonly Len _len = new(), _repLen = new();
        readonly ushort[] _literal;
        readonly int _lc, _lp, _pb;

        Decoder(byte[] input, int start, int props)
        {
            _in = input;
            _pos = start;
            _lc = props % 9; props /= 9; _lp = props % 5; _pb = props / 5;
            _literal = new ushort[0x300 << (_lc + _lp)];
            for (int i = 0; i < LenToPosStates; i++) _posSlot[i] = new ushort[1 << 6];
            foreach (var a in new[] { _isMatch, _isRep, _isRepG0, _isRepG1, _isRepG2, _isRep0Long, _posDecoders, _align, _literal }
                         .Concat(_posSlot)) Array.Fill(a, (ushort)1024);
            for (int i = 0; i < 5; i++) _code = (_code << 8) | Next();
        }

        byte Next() => _pos < _in.Length ? _in[_pos++] : throw new InvalidDataException("lzma: input ends early");

        void Normalize()
        {
            if (_range < 1u << 24) { _range <<= 8; _code = (_code << 8) | Next(); }
        }

        uint Bit(ushort[] p, int i)
        {
            uint bound = (_range >> 11) * p[i];
            uint bit;
            if (_code < bound) { _range = bound; p[i] += (ushort)((2048 - p[i]) >> 5); bit = 0; }
            else { _range -= bound; _code -= bound; p[i] -= (ushort)(p[i] >> 5); bit = 1; }
            Normalize();
            return bit;
        }

        uint Direct(int count)
        {
            uint result = 0;
            for (; count > 0; count--)
            {
                _range >>= 1;
                uint t = (_code - _range) >> 31;
                _code -= _range & (t - 1);
                result = (result << 1) | (1 - t);
                Normalize();
            }
            return result;
        }

        uint Tree(ushort[] p, int offset, int bits)
        {
            uint m = 1;
            for (int i = 0; i < bits; i++) m = (m << 1) + Bit(p, offset + (int)m);
            return m - (1u << bits);
        }

        uint ReverseTree(ushort[] p, int offset, int bits)
        {
            uint m = 1, symbol = 0;
            for (int i = 0; i < bits; i++)
            {
                uint bit = Bit(p, offset + (int)m);
                m = (m << 1) + bit;
                symbol |= bit << i;
            }
            return symbol;
        }

        sealed class Len
        {
            public readonly ushort[] Choice = [1024, 1024], Low = new ushort[PosStatesMax << LowBits],
                Mid = new ushort[PosStatesMax << MidBits], High = new ushort[1 << HighBits];
            public Len() { Array.Fill(Low, (ushort)1024); Array.Fill(Mid, (ushort)1024); Array.Fill(High, (ushort)1024); }
        }

        uint Length(Len l, int posState)
        {
            if (Bit(l.Choice, 0) == 0) return Tree(l.Low, posState << LowBits, LowBits);
            if (Bit(l.Choice, 1) == 0) return (1 << LowBits) + Tree(l.Mid, posState << MidBits, MidBits);
            return (1 << LowBits) + (1 << MidBits) + Tree(l.High, 0, HighBits);
        }

        public static bool Run(byte[] input, int start, int props, byte[] output)
        {
            var d = new Decoder(input, start, props);
            int pbMask = (1 << d._pb) - 1, lpMask = (1 << d._lp) - 1;
            uint rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0;
            int state = 0, outPos = 0;
            byte prev = 0;
            while (outPos < output.Length)
            {
                int posState = outPos & pbMask;
                if (d.Bit(d._isMatch, (state << 4) + posState) == 0)
                {
                    int lit = 0x300 * (((outPos & lpMask) << d._lc) + (prev >> (8 - d._lc)));
                    uint symbol = 1;
                    if (state >= 7)
                    {
                        uint match = output[outPos - rep0 - 1];
                        do
                        {
                            uint matchBit = (match >> 7) & 1;
                            match <<= 1;
                            uint bit = d.Bit(d._literal, lit + (int)(((1 + matchBit) << 8) + symbol));
                            symbol = (symbol << 1) | bit;
                            if (matchBit != bit)
                            {
                                while (symbol < 0x100) symbol = (symbol << 1) | d.Bit(d._literal, lit + (int)symbol);
                                break;
                            }
                        } while (symbol < 0x100);
                    }
                    else
                        while (symbol < 0x100) symbol = (symbol << 1) | d.Bit(d._literal, lit + (int)symbol);
                    prev = output[outPos++] = (byte)symbol;
                    state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
                    continue;
                }
                uint len;
                if (d.Bit(d._isRep, state) == 1)
                {
                    if (outPos == 0) return false;
                    if (d.Bit(d._isRepG0, state) == 0)
                    {
                        if (d.Bit(d._isRep0Long, (state << 4) + posState) == 0)
                        {
                            state = state < 7 ? 9 : 11;
                            prev = output[outPos] = output[outPos - rep0 - 1];
                            outPos++;
                            continue;
                        }
                    }
                    else
                    {
                        uint dist;
                        if (d.Bit(d._isRepG1, state) == 0) dist = rep1;
                        else
                        {
                            if (d.Bit(d._isRepG2, state) == 0) dist = rep2;
                            else { dist = rep3; rep3 = rep2; }
                            rep2 = rep1;
                        }
                        rep1 = rep0;
                        rep0 = dist;
                    }
                    len = d.Length(d._repLen, posState);
                    state = state < 7 ? 8 : 11;
                }
                else
                {
                    rep3 = rep2; rep2 = rep1; rep1 = rep0;
                    len = d.Length(d._len, posState);
                    state = state < 7 ? 7 : 10;
                    uint slot = d.Tree(d._posSlot[Math.Min((int)len, LenToPosStates - 1)], 0, 6);
                    if (slot >= 4)
                    {
                        int direct = (int)(slot >> 1) - 1;
                        rep0 = (2 | (slot & 1)) << direct;
                        if (slot < EndPosModelIndex) rep0 += d.ReverseTree(d._posDecoders, (int)(rep0 - slot) - 1, direct);
                        else
                        {
                            rep0 += d.Direct(direct - AlignBits) << AlignBits;
                            rep0 += d.ReverseTree(d._align, 0, AlignBits);
                            if (rep0 == 0xFFFFFFFF) break; // end marker
                        }
                    }
                    else rep0 = slot;
                }
                len += MatchMinLen;
                if (rep0 >= outPos) return false;
                for (; len > 0 && outPos < output.Length; len--)
                {
                    prev = output[outPos] = output[outPos - rep0 - 1];
                    outPos++;
                }
            }
            return outPos == output.Length;
        }
    }
}
