using System;
using System.Globalization;

namespace Fdo.Transport;

/// <summary>
/// An FDO wire protocol version, encoded as <c>protver</c> (FDO 2.0 §3.2):
/// major * 100 + minor, with a minor version below 100.
/// </summary>
internal readonly struct FdoProtocolVersion : IEquatable<FdoProtocolVersion>
{
    /// <summary>
    /// FDO 2.0, whose <c>protver</c> value is 200.
    /// </summary>
    public static FdoProtocolVersion V20 { get; } = new(2, 0);

    /// <summary>
    /// Creates a protocol version from its major and minor components.
    /// </summary>
    /// <param name="major">The major version, at least 1.</param>
    /// <param name="minor">The minor version, from 0 to 99.</param>
    public FdoProtocolVersion(int major, int minor)
    {
        if (minor is < 0 or > 99)
        {
            throw new ArgumentOutOfRangeException(nameof(minor), minor, "The minor version must be from 0 to 99.");
        }

        if (major < 1 || major > (ushort.MaxValue - minor) / 100)
        {
            throw new ArgumentOutOfRangeException(nameof(major), major, "The encoded version must fit in 16 bits.");
        }

        Value = (ushort)((major * 100) + minor);
    }

    /// <summary>
    /// The encoded <c>protver</c> value.
    /// </summary>
    public ushort Value { get; }

    /// <summary>
    /// The major version.
    /// </summary>
    public int Major => Value / 100;

    /// <summary>
    /// The minor version.
    /// </summary>
    public int Minor => Value % 100;

    /// <inheritdoc/>
    public bool Equals(FdoProtocolVersion other) => Value == other.Value;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is FdoProtocolVersion other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => Value;

    /// <inheritdoc/>
    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Compares two versions for equality.
    /// </summary>
    public static bool operator ==(FdoProtocolVersion left, FdoProtocolVersion right) => left.Equals(right);

    /// <summary>
    /// Compares two versions for inequality.
    /// </summary>
    public static bool operator !=(FdoProtocolVersion left, FdoProtocolVersion right) => !left.Equals(right);
}
