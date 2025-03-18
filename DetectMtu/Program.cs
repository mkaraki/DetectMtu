using System.Net.NetworkInformation;

namespace DetectMtu;

internal static class Program
{
    private const string V4Endpoint = "1.1.1.1";
    private const string V6Endpoint = "2606:4700:4700::1111";

    private static async Task Main()
    {
        var v4Mtu = await DetectV4MtuAsync();
        if (v4Mtu == 0)
            await Console.Error.WriteLineAsync("Failed to detect v4 MTU");
        else
            Console.WriteLine($"v4 MTU: {v4Mtu}, MSS: {v4Mtu - 40 /* 20 for v4 header, 20 for TCP header */}");

        var v6Mtu = await DetectV6MtuAsync();
        if (v6Mtu == 0)
            await Console.Error.WriteLineAsync("Failed to detect v6 MTU");
        else
            Console.WriteLine($"v6 MTU: {v6Mtu}, MSS: {v6Mtu - 60 /* 40 for v6 header, 20 for TCP header */}");
    }

    private static async Task<int> DetectV4MtuAsync()
    {
        var res = await BinarySearchIcmpNoFragmentSize(
            V4Endpoint,
            1,
            1472 // 1500 - 20 - 8: 20 bytes for IP header, 8 bytes for ICMP header
        );

        if (res == 0)
        {
            return 0;
        }

        return res + 28; // 20 bytes for IP header, 8 bytes for ICMP header
    }

    private static async Task<int> DetectV6MtuAsync()
    {
        var res = await BinarySearchIcmpNoFragmentSize(
            V6Endpoint,
            1,
            1452 // 1500 - 40 - 8: 40 bytes for IP header, 8 bytes for ICMP header
        );

        if (res == 0)
        {
            return 0;
        }

        return res + 48; // 40 bytes for IP header, 8 bytes for ICMP header
    }

    private static async Task<int> BinarySearchIcmpNoFragmentSize(string endpoint, int min, int max)
    {
        max += 1; // Binary search is exclusive on the upper bound

        while (min < max)
        {
            var mid = (max - min) / 2 + min;
            Console.Write($"Try {mid}\r");

            var isSuccess = await SendPing(endpoint, mid);

            if (!isSuccess.HasValue)
            {
                return 0;
            }

            if (isSuccess.Value)
            {
                min = mid + 1;
            }
            else
            {
                max = mid;
            }
        }

        return min - 1;
    }

    private static readonly Ping PingSender = new();
    private static readonly PingOptions PingOptions = new(64, true);

    private static async Task<bool?> SendPing(string endpoint, int size)
    {
        var buffer = new byte[size];

        for (var i = 0; i < 3; i++)
        {
            var reply = await PingSender.SendPingAsync(endpoint, 2000, buffer, PingOptions);

            if (reply.Status is IPStatus.Success or IPStatus.PacketTooBig)
            {
                return reply.Status == IPStatus.Success;
            }

            await Task.Delay(2000);
        }

        return null;
    }
}
