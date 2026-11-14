using System.Collections.Generic;
using Probe.Ext;

var items = new List<string>().AddDefaults();
System.Console.WriteLine(items.Count + new Padded().Pad());
