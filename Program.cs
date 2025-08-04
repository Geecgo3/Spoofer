using System;
using System.Collections.Generic;
using System.Management;
using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace Spoofer
{
    internal class Program
    {
        // Win32 API calls to disable/enable network adapter
        [DllImport("setupapi.dll", SetLastError = true)]
        static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid, IntPtr Enumerator, IntPtr hwndParent, uint Flags);

        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool SetupDiEnumDeviceInfo(IntPtr DeviceInfoSet, uint MemberIndex, ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool SetupDiSetClassInstallParams(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData,
            ref SP_PROPCHANGE_PARAMS ClassInstallParams, int ClassInstallParamsSize);

        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool SetupDiCallClassInstaller(uint InstallFunction, IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        const uint DIGCF_PRESENT = 0x00000002;
        const uint DIGCF_PROFILE = 0x00000008;
        const uint DIF_PROPERTYCHANGE = 0x12;
        const uint DICS_ENABLE = 1;
        const uint DICS_DISABLE = 2;
        const uint DICS_FLAG_GLOBAL = 1;

        [StructLayout(LayoutKind.Sequential)]
        struct SP_DEVINFO_DATA
        {
            public int cbSize;
            public Guid ClassGuid;
            public uint DevInst;
            public IntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SP_CLASSINSTALL_HEADER
        {
            public uint cbSize;
            public uint InstallFunction;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SP_PROPCHANGE_PARAMS
        {
            public SP_CLASSINSTALL_HEADER ClassInstallHeader;
            public uint StateChange;
            public uint Scope;
            public uint HwProfile;
        }

        static void Main(string[] args)
        {
            try
            {
                Console.WriteLine("Listing all network adapters with MAC addresses:\n");

                // Get all adapters with WMI
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter = TRUE AND MACAddress IS NOT NULL");
                var adapters = new List<ManagementObject>();
                int i = 0;
                foreach (ManagementObject obj in searcher.Get())
                {
                    string name = obj["Name"]?.ToString();
                    string mac = obj["MACAddress"]?.ToString();
                    Console.WriteLine($"{i}: {name} - {mac}");
                    adapters.Add(obj);
                    i++;
                }

                if (adapters.Count == 0)
                {
                    Console.WriteLine("No physical network adapters found.");
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey();
                    return;
                }

                int selectedIndex = -1;
                while (true)
                {
                    Console.WriteLine("\nSelect adapter to spoof MAC (index):");
                    string input = Console.ReadLine();
                    if (int.TryParse(input, out selectedIndex) && selectedIndex >= 0 && selectedIndex < adapters.Count)
                        break;

                    Console.WriteLine("Invalid input. Please enter a valid number from the list.");
                }

                var selectedAdapter = adapters[selectedIndex];
                string originalMac = selectedAdapter["MACAddress"].ToString();
                string deviceId = selectedAdapter["PNPDeviceID"].ToString();

                Console.WriteLine($"Selected adapter: {selectedAdapter["Name"]}");
                Console.WriteLine($"Original MAC: {originalMac}");

                // Generate random MAC address (locally administered unicast)
                string randomMac = GenerateRandomMacAddress();
                Console.WriteLine($"Random MAC to spoof: {randomMac}");

                // Spoof the MAC address
                bool success = SetMacAddress(deviceId, randomMac);
                if (!success)
                {
                    Console.WriteLine("Failed to set MAC address.");
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey();
                    return;
                }

                Console.WriteLine("MAC address spoofed. Disabling and enabling adapter to apply changes...");
                bool disabled = SetNetworkAdapterEnabled(deviceId, false);
                if (!disabled)
                {
                    Console.WriteLine("Failed to disable network adapter.");
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey();
                    return;
                }

                System.Threading.Thread.Sleep(2000);

                bool enabled = SetNetworkAdapterEnabled(deviceId, true);
                if (!enabled)
                {
                    Console.WriteLine("Failed to enable network adapter.");
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey();
                    return;
                }

                Console.WriteLine("Adapter re-enabled with spoofed MAC.");

                Console.WriteLine("\nPress Enter to revert the MAC address and exit.");
                Console.ReadLine();

                // Revert MAC address on exit
                Console.WriteLine("Reverting MAC address...");
                SetMacAddress(deviceId, null);

                Console.WriteLine("Disabling and enabling adapter to apply original MAC...");
                SetNetworkAdapterEnabled(deviceId, false);
                System.Threading.Thread.Sleep(2000);
                SetNetworkAdapterEnabled(deviceId, true);

                Console.WriteLine("Done. Press any key to exit.");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unexpected error: " + ex.Message);
                Console.WriteLine("Press any key to exit.");
                Console.ReadKey();
            }
        }


        static string GenerateRandomMacAddress()
        {
            Random rnd = new Random();
            byte[] macBytes = new byte[6];
            rnd.NextBytes(macBytes);

            // Set locally administered and unicast bits
            macBytes[0] = (byte)(macBytes[0] & 0xFE);  // Unicast
            macBytes[0] = (byte)(macBytes[0] | 0x02);  // Locally administered

            return BitConverter.ToString(macBytes).Replace("-", "");
        }

        static bool SetMacAddress(string deviceId, string mac)
        {
            string regPath = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";

            try
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                    .OpenSubKey(regPath, RegistryKeyPermissionCheck.ReadWriteSubTree))
                {
                    if (baseKey == null)
                    {
                        Console.WriteLine("Failed to open registry key.");
                        return false;
                    }

                    foreach (var subkeyName in baseKey.GetSubKeyNames())
                    {
                        using (RegistryKey subkey = baseKey.OpenSubKey(subkeyName, writable: true))
                        {
                            if (subkey == null) continue;

                            string regDeviceId = subkey.GetValue("NetCfgInstanceId") as string;
                            if (string.Equals(regDeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
                            {
                                if (mac == null)
                                {
                                    if (subkey.GetValue("NetworkAddress") != null)
                                        subkey.DeleteValue("NetworkAddress");
                                }
                                else
                                {
                                    subkey.SetValue("NetworkAddress", mac, RegistryValueKind.String);
                                }
                                return true;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error setting MAC address in registry: " + ex.Message);
            }

            return false;
        }

        static bool SetNetworkAdapterEnabled(string deviceId, bool enable)
        {
            var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_NetworkAdapter WHERE PNPDeviceID = '{deviceId.Replace("\\", "\\\\")}'");
            foreach (ManagementObject obj in searcher.Get())
            {
                try
                {
                    var result = enable ? obj.InvokeMethod("Enable", null) : obj.InvokeMethod("Disable", null);
                    return (uint)result == 0;
                }
                catch (ManagementException ex)
                {
                    Console.WriteLine($"ManagementException: {ex.Message}");
                    return false;
                }
            }
            return false;
        }

    }
}
