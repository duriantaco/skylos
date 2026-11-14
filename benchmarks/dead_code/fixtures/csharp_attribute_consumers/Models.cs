using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using CommunityToolkit.Mvvm.Input;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace Probe.Views;

public partial class BadgeViewModel
{
    [RelayCommand]
    private void Save()
    {
    }

    [Obsolete("use Save")]
    private void OldSave()
    {
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int FastOrphan()
    {
        return 1;
    }

    private void PlainOrphan()
    {
    }
}

public class CatalogServices(CatalogContext context)
{
    public CatalogContext Context { get; } = context;
}

internal class OrphanServices(CatalogContext context)
{
    public CatalogContext Context { get; } = context;
}

public class CatalogContext : DbContext
{
}

[DbContext(typeof(CatalogContext))]
partial class CatalogContextModelSnapshot : ModelSnapshot
{
}

[Serializable]
internal class OrphanSnapshot
{
}

[StructLayout(LayoutKind.Sequential)]
struct InlineSlots
{
    object? Slot1;
    object? Slot2;

    public Span<object?> AsSpan()
    {
        return MemoryMarshal.CreateSpan(ref Slot1, 2);
    }
}

struct PlainSlots
{
    object? Used;
    object? OrphanSlot;

    public object? Read()
    {
        return Used;
    }
}
