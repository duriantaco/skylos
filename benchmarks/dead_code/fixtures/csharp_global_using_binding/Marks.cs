using System;

namespace Probe.Marks;

[AttributeUsage(AttributeTargets.Method)]
sealed class TracedAttribute : Attribute
{
}

[AttributeUsage(AttributeTargets.Method)]
sealed class OrphanMarkAttribute : Attribute
{
}
