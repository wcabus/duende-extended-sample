// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Configuration;

internal static class ConfigurationExtensions
{
    public static TimeSpan? GetTimeSpan(this IConfiguration configuration, string key)
    {
        var value = configuration[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (value.StartsWith("P") || value.StartsWith("-P"))
        {
            return ParseDuration(value);
        }

        if (TimeSpan.TryParse(value, out var result))
        {
            return result;
        }

        return null;
    }

    private static TimeSpan? ParseDuration(string duration)
    {
        if (string.IsNullOrWhiteSpace(duration))
        {
            return null;
        }

        if (!duration.StartsWith("P") && !duration.StartsWith("-P"))
        {
            return null;
        }

        var negative = duration.StartsWith("-");

        var startPos = duration.IndexOf("P", StringComparison.Ordinal) + 1;
        var timeMarkerPassed = false;
        if (duration[startPos] == 'T')
        {
            // Only a time duration is specified
            timeMarkerPassed = true;
            startPos++;
        }

        var timeParts = new List<(int Number, char Marker, bool TimeMarker)>();
        var pos = startPos;
        while (pos < duration.Length)
        {
            switch (duration[pos])
            {
                case 'Y':
                case 'M':
                case 'D':
                case 'H':
                case 'S':
                    // parse the number between startPos and pos together with the indicators
                    if (int.TryParse(duration.Substring(startPos, pos - startPos), out var number))
                    {
                        timeParts.Add((number, duration[pos], timeMarkerPassed));
                    }
                    else
                    {
                        return null; // invalid number defined, so invalid duration.
                    }

                    pos++;
                    startPos = pos; // Mark the start of a potential next value
                    break;
                case 'T':
                    if (timeMarkerPassed)
                    {
                        return null; // double time marker, invalid duration.
                    }

                    timeMarkerPassed = true;
                    pos++;
                    startPos = pos; // Mark the start of a potential next value
                    break;
                default:
                    // inside a value
                    pos++;
                    break;
            }
        }

        var timespan = TimeSpan.Zero;
        foreach (var timePart in timeParts)
        {
            switch (timePart.Marker)
            {
                case 'Y':
                    timespan = timespan.Add(TimeSpan.FromDays(365 * timePart.Number));
                    break;
                case 'M':
                    timespan = timespan.Add(timePart.TimeMarker
                        ? TimeSpan.FromMinutes(timePart.Number)
                        : TimeSpan.FromDays(30 * timePart.Number));
                    break;
                case 'D':
                    timespan = timespan.Add(TimeSpan.FromDays(timePart.Number));
                    break;
                case 'H':
                    timespan = timespan.Add(TimeSpan.FromHours(timePart.Number));
                    break;
                case 'S':
                    timespan = timespan.Add(TimeSpan.FromSeconds(timePart.Number));
                    break;
            }
        }

        return negative ? timespan.Negate() : timespan;
    }
}