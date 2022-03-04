<#
.SYNOPSIS
   This script demonstrates an xVC-vMotion where a running Virtual Machine
   is live migrated between two vCenter Servers which are NOT part of the
   same SSO Domain which is only available using the vSphere 6.0 API.

   This script also supports live migrating a running Virtual Machine between
   two vCenter Servers that ARE part of the same SSO Domain (aka Enhanced Linked Mode)

   This script also supports migrating VMs connected to both a VSS/VDS as well as having multiple vNICs

   This script also supports migrating to/from VMware Cloud on AWS (VMC)
.NOTES
   File Name  : xMove-VM.ps1
   Author     : William Lam - @lamw
   Version    : 1.0

   Updated by  : Askar Kopbayev - @akopbayev
   Version     : 1.1
   Description : The script allows to run compute-only xVC-vMotion when the source VM has multiple disks on differnet datastores.

   Updated by  : William Lam - @lamw
   Version     : 1.2
   Description : Added additional parameters to be able to perform cold migration to/from VMware Cloud on AWS (VMC)
                 -ResourcePool
                 -uppercaseuuid

.LINK
    http://www.williamlam.com/2016/05/automating-cross-vcenter-vmotion-xvc-vmotion-between-the-same-different-sso-domain.html
.LINK
   https://github.com/lamw

.INPUTS
   sourceVCConnection, destVCConnection, vm, switchtype, switch,
   cluster, resourcepool, datastore, vmhost, vmnetworks, $xvctype, $uppercaseuuid
.OUTPUTS
   Console output
#>

Function xMove-VM {
    param(
    [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)
    ]
    [VMware.VimAutomation.ViCore.Util10.VersionedObjectImpl]$sourcevc,
    [VMware.VimAutomation.ViCore.Util10.VersionedObjectImpl]$destvc,
    [String]$vm,
    [String]$switchtype,
    [String]$switch,
    [String]$cluster,
    [String]$resourcepool,
    [String]$datastore,
    [String]$vmhost,
    [String]$vmnetworks,
    [Int]$xvctype,
    [Boolean]$uppercaseuuid
    )

    # Retrieve Source VC SSL Thumbprint
    $vcurl = "https://" + $destVC
add-type @"
#     if ($TrustAllCertificates) {
#         # Create a compilation environment
#         $Provider=New-Object Microsoft.CSharp.CSharpCodeProvider
#         $Compiler=$Provider.CreateCompiler()
#         $Params=New-Object System.CodeDom.Compiler.CompilerParameters
#         $Params.GenerateExecutable=$False
#         $Params.GenerateInMemory=$True
#         $Params.IncludeDebugInformation=$False
#         $Params.ReferencedAssemblies.Add("System.DLL") > $null
#         $TASource=@'
# namespace Local.ToolkitExtensions.Net.CertificatePolicy {
#     public class TrustAll : System.Net.ICertificatePolicy {
#         public TrustAll() {}
#         public bool CheckValidationResult(
#             System.Net.ServicePoint sp,
#                 System.Security.Cryptography.X509Certificates.X509Certificate cert,
#                 System.Net.WebRequest req,
#                 int problem
#         ) {
#             return true;
#         }
#     }
# }
# '@
#         $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
#         $TAAssembly=$TAResults.CompiledAssembly

#         ## We now create an instance of the TrustAll and attach it to the ServicePointManager
#         $TrustAll=$TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
#         [System.Net.ServicePointManager]::CertificatePolicy=$TrustAll
#     }
# if ($PSVersionTable.PSVersion.Major -gt 5) {
#     $Param.SkipHeaderValidation = $ignoreCertFailure
#     $Param.SkipCertificateCheck = $ignoreCertFailure
# } else {
#     Ignore-SSLCertificates
# }


# ! ERRORS in PS 7
    if ($TrustAllCerts){
        $TypeDefinition = @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public TrustAllCertsPolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint,
                X509Certificate cert,
                WebRequest wRequest,
                int certProb
            ) {
                    return true;
            }
        }
"@

        if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
            Add-Type -TypeDefinition $TypeDefinition
        }
    }
    # Need to do simple GET connection for this method to work
    Invoke-RestMethod -Uri $VCURL -Method Get | Out-Null

    $endpoint_request = [System.Net.Webrequest]::Create("$vcurl")
    # Get Thumbprint + add colons for a valid Thumbprint
    $destVCThumbprint = ($endpoint_request.ServicePoint.Certificate.GetCertHashString()) -replace '(..(?!$))','$1:'

    # Source VM to migrate
    $vm_view = Get-View (Get-VM -Server $sourcevc -Name $vm) -Property Config.Hardware.Device

    # Dest Datastore to migrate VM to
    $datastore_view = (Get-Datastore -Server $destVCConn -Name $datastore)

    # Dest Cluster/ResourcePool to migrate VM to
    if($cluster) {
        $cluster_view = (Get-Cluster -Server $destVCConn -Name $cluster)
        $resource = $cluster_view.ExtensionData.resourcePool
    } else {
        $rp_view = (Get-ResourcePool -Server $destVCConn -Name $resourcepool)
        $resource = $rp_view.ExtensionData.MoRef
    }

    # Dest ESXi host to migrate VM to
    $vmhost_view = (Get-VMHost -Server $destVCConn -Name $vmhost)
<#
#---------------CheckRelocate_Task---------------
$vm = New-Object VMware.Vim.ManagedObjectReference
$vm.Type = 'VirtualMachine'
$vm.Value = 'vm-109830'
$spec = New-Object VMware.Vim.VirtualMachineRelocateSpec
$spec.Service = New-Object VMware.Vim.ServiceLocator
$spec.Service.Credential = New-Object VMware.Vim.ServiceLocatorSAMLCredential
$spec.Service.Credential.Token = 'Sensitive data is not recorded'
$spec.Service.SslThumbprint = 'F2:98:C3:B8:0C:46:87:76:13:88:D9:46:B1:B7:10:90:66:92:82:1E'
$spec.Service.InstanceUuid = '1bd6fbc3-30cd-4e97-be3b-48ca8bc30482'
$spec.Service.Url = 'https://DLC-VCSA.Prod-iNet.com:443/sdk'
$spec.Pool = New-Object VMware.Vim.ManagedObjectReference
$spec.Pool.Type = 'ResourcePool'
$spec.Pool.Value = 'resgroup-64'
$testType = New-Object String[] (3)
$testType[0] = 'sourceTests'
$testType[1] = 'resourcePoolTests'
$testType[2] = 'hostTests'
$_this = Get-View -Id 'VirtualMachineProvisioningChecker-ProvChecker' -Server (Get-VcConnection -VcInstanceUuid '0b18a878-c2f9-40ac-b36d-efb68941cc52')
$_this.CheckRelocate_Task($vm, $spec, $testType)
#>

    # Find all Etherenet Devices for given VM which
    # we will need to change its network at the destination
    $vmNetworkAdapters = @()
    $devices = $vm_view.Config.Hardware.Device
    foreach ($device in $devices) {
        if($device -is [VMware.Vim.VirtualEthernetCard]) {
            $vmNetworkAdapters += $device
        }
    }
<#
#---------------CheckRelocate_Task---------------
$vm = New-Object VMware.Vim.ManagedObjectReference
$vm.Type = 'VirtualMachine'
$vm.Value = 'vm-109830'
$spec = New-Object VMware.Vim.VirtualMachineRelocateSpec
$spec.Disk = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator[] (2)
$spec.Disk[0] = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator
$spec.Disk[0].Datastore = New-Object VMware.Vim.ManagedObjectReference
$spec.Disk[0].Datastore.Type = 'Datastore'
$spec.Disk[0].Datastore.Value = 'datastore-2045'
$spec.Disk[0].DiskId = 2000
$spec.Disk[1] = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator
$spec.Disk[1].Datastore = New-Object VMware.Vim.ManagedObjectReference
$spec.Disk[1].Datastore.Type = 'Datastore'
$spec.Disk[1].Datastore.Value = 'datastore-2045'
$spec.Disk[1].DiskId = 2001
$spec.Datastore = New-Object VMware.Vim.ManagedObjectReference
$spec.Datastore.Type = 'Datastore'
$spec.Datastore.Value = 'datastore-2045'
$spec.Service = New-Object VMware.Vim.ServiceLocator
$spec.Service.Credential = New-Object VMware.Vim.ServiceLocatorSAMLCredential
$spec.Service.Credential.Token = 'Sensitive data is not recorded'
$spec.Service.SslThumbprint = 'F2:98:C3:B8:0C:46:87:76:13:88:D9:46:B1:B7:10:90:66:92:82:1E'
$spec.Service.InstanceUuid = '1bd6fbc3-30cd-4e97-be3b-48ca8bc30482'
$spec.Service.Url = 'https://DLC-VCSA.Prod-iNet.com:443/sdk'
$spec.Pool = New-Object VMware.Vim.ManagedObjectReference
$spec.Pool.Type = 'ResourcePool'
$spec.Pool.Value = 'resgroup-64'
$testType = New-Object String[] (4)
$testType[0] = 'sourceTests'
$testType[1] = 'resourcePoolTests'
$testType[2] = 'datastoreTests'
$testType[3] = 'hostTests'
$_this = Get-View -Id 'VirtualMachineProvisioningChecker-ProvChecker' -Server (Get-VcConnection -VcInstanceUuid '0b18a878-c2f9-40ac-b36d-efb68941cc52')
$_this.CheckRelocate_Task($vm, $spec, $testType)
#>

    # Relocate Spec for Migration
    $spec = New-Object VMware.Vim.VirtualMachineRelocateSpec
    $spec.datastore = $datastore_view.Id
    $spec.host = $vmhost_view.Id
    $spec.pool = $resource

    # Relocate Spec Disk Locator
    if($xvctype -eq 1){
        $HDs = Get-VM -Server $sourcevc -Name $vm | Get-HardDisk
        $HDs | %{
            $disk = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator
            $disk.diskId = $_.Extensiondata.Key
            $SourceDS = $_.FileName.Split("]")[0].TrimStart("[")
            $DestDS = Get-Datastore -Server $destvc -name $sourceDS
            $disk.Datastore = $DestDS.ID
            $spec.disk += $disk
        }
    }

    # Service Locator for the destination vCenter Server
    # regardless if its within same SSO Domain or not
    $service = New-Object VMware.Vim.ServiceLocator
    $credential = New-Object VMware.Vim.ServiceLocatorNamePassword
    $credential.username = $destVCusername
    $credential.password = $destVCpassword
    $service.credential = $credential
    # For some xVC-vMotion, VC's InstanceUUID must be in all caps
    # Haven't figured out why, but this flag would allow user to toggle (default=false)
    if($uppercaseuuid) {
        $service.instanceUuid = $destVCConn.InstanceUuid
    } else {
        $service.instanceUuid = ($destVCConn.InstanceUuid).ToUpper()
    }
    $service.sslThumbprint = $destVCThumbprint
    $service.url = "https://$destVC"
    $spec.service = $service

    # Create VM spec depending if destination networking
    # is using Distributed Virtual Switch (VDS) or
    # is using Virtual Standard Switch (VSS)
    $count = 0
    if($switchtype -eq "vds") {
        foreach ($vmNetworkAdapter in $vmNetworkAdapters) {
            # New VM Network to assign vNIC
            $vmnetworkname = ($vmnetworks -split ",")[$count]

            # Extract Distributed Portgroup required info
            $dvpg = Get-VDPortgroup -Server $destvc -Name $vmnetworkname
            $vds_uuid = (Get-View $dvpg.ExtensionData.Config.DistributedVirtualSwitch).Uuid
            $dvpg_key = $dvpg.ExtensionData.Config.key

            # Device Change spec for VSS portgroup
            $dev = New-Object VMware.Vim.VirtualDeviceConfigSpec
            $dev.Operation = "edit"
            $dev.Device = $vmNetworkAdapter
            $dev.device.Backing = New-Object VMware.Vim.VirtualEthernetCardDistributedVirtualPortBackingInfo
            $dev.device.backing.port = New-Object VMware.Vim.DistributedVirtualSwitchPortConnection
            $dev.device.backing.port.switchUuid = $vds_uuid
            $dev.device.backing.port.portgroupKey = $dvpg_key
            $spec.DeviceChange += $dev
            $count++
        }
    } else {
        foreach ($vmNetworkAdapter in $vmNetworkAdapters) {
            # New VM Network to assign vNIC
            $vmnetworkname = ($vmnetworks -split ",")[$count]

            # Device Change spec for VSS portgroup
            $dev = New-Object VMware.Vim.VirtualDeviceConfigSpec
            $dev.Operation = "edit"
            $dev.Device = $vmNetworkAdapter
            $dev.device.backing = New-Object VMware.Vim.VirtualEthernetCardNetworkBackingInfo
            $dev.device.backing.deviceName = $vmnetworkname
            $spec.DeviceChange += $dev
            $count++
        }
    }
<#
#---------------CheckRelocate_Task---------------
$vm = New-Object VMware.Vim.ManagedObjectReference
$vm.Type = 'VirtualMachine'
$vm.Value = 'vm-109830'
$spec = New-Object VMware.Vim.VirtualMachineRelocateSpec
$spec.DeviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec[] (1)
$spec.DeviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec
$spec.DeviceChange[0].Device = New-Object VMware.Vim.VirtualVmxnet3
$spec.DeviceChange[0].Device.MacAddress = '00:50:56:b3:ca:2f'
$spec.DeviceChange[0].Device.ResourceAllocation = New-Object VMware.Vim.VirtualEthernetCardResourceAllocation
$spec.DeviceChange[0].Device.ResourceAllocation.Limit = -1
$spec.DeviceChange[0].Device.ResourceAllocation.Reservation = 0
$spec.DeviceChange[0].Device.ResourceAllocation.Share = New-Object VMware.Vim.SharesInfo
$spec.DeviceChange[0].Device.ResourceAllocation.Share.Shares = 50
$spec.DeviceChange[0].Device.ResourceAllocation.Share.Level = 'normal'
$spec.DeviceChange[0].Device.Connectable = New-Object VMware.Vim.VirtualDeviceConnectInfo
$spec.DeviceChange[0].Device.Connectable.Connected = $true
$spec.DeviceChange[0].Device.Connectable.MigrateConnect = 'unset'
$spec.DeviceChange[0].Device.Connectable.AllowGuestControl = $true
$spec.DeviceChange[0].Device.Connectable.StartConnected = $true
$spec.DeviceChange[0].Device.Connectable.Status = 'ok'
$spec.DeviceChange[0].Device.Backing = New-Object VMware.Vim.VirtualEthernetCardDistributedVirtualPortBackingInfo
$spec.DeviceChange[0].Device.Backing.Port = New-Object VMware.Vim.DistributedVirtualSwitchPortConnection
$spec.DeviceChange[0].Device.Backing.Port.SwitchUuid = '50 0c d1 86 75 47 0a 57-3c c1 98 e3 6b 36 6e 03'
$spec.DeviceChange[0].Device.Backing.Port.PortgroupKey = 'dvportgroup-2085'
$spec.DeviceChange[0].Device.AddressType = 'assigned'
$spec.DeviceChange[0].Device.ControllerKey = 100
$spec.DeviceChange[0].Device.UnitNumber = 7
$spec.DeviceChange[0].Device.WakeOnLanEnabled = $true
$spec.DeviceChange[0].Device.SlotInfo = New-Object VMware.Vim.VirtualDevicePciBusSlotInfo
$spec.DeviceChange[0].Device.SlotInfo.PciSlotNumber = 192
$spec.DeviceChange[0].Device.UptCompatibilityEnabled = $true
$spec.DeviceChange[0].Device.DeviceInfo = New-Object VMware.Vim.Description
$spec.DeviceChange[0].Device.DeviceInfo.Summary = 'DVSwitch: 50 33 5b 75 f0 ae 7a c1-eb d5 6c 3c cb 7b 39 03'
$spec.DeviceChange[0].Device.DeviceInfo.Label = 'Network adapter 1'
$spec.DeviceChange[0].Device.Key = 4000
$spec.DeviceChange[0].Operation = 'edit'
$spec.Service = New-Object VMware.Vim.ServiceLocator
$spec.Service.Credential = New-Object VMware.Vim.ServiceLocatorSAMLCredential
$spec.Service.Credential.Token = 'Sensitive data is not recorded'
$spec.Service.SslThumbprint = 'F2:98:C3:B8:0C:46:87:76:13:88:D9:46:B1:B7:10:90:66:92:82:1E'
$spec.Service.InstanceUuid = '1bd6fbc3-30cd-4e97-be3b-48ca8bc30482'
$spec.Service.Url = 'https://DLC-VCSA.Prod-iNet.com:443/sdk'
$spec.Pool = New-Object VMware.Vim.ManagedObjectReference
$spec.Pool.Type = 'ResourcePool'
$spec.Pool.Value = 'resgroup-64'
$testType = New-Object String[] (4)
$testType[0] = 'sourceTests'
$testType[1] = 'resourcePoolTests'
$testType[2] = 'hostTests'
$testType[3] = 'networkTests'
$_this = Get-View -Id 'VirtualMachineProvisioningChecker-ProvChecker' -Server (Get-VcConnection -VcInstanceUuid '0b18a878-c2f9-40ac-b36d-efb68941cc52')
$_this.CheckRelocate_Task($vm, $spec, $testType)
#>

    Write-Host "`nMigrating $vmname from $sourceVC to $destVC ...`n"

<#
#---------------FindRulesForVm---------------
$vm = New-Object VMware.Vim.ManagedObjectReference
$vm.Type = 'VirtualMachine'
$vm.Value = 'vm-109830'
$_this = Get-View -Id 'ClusterComputeResource-domain-c14769' -Server (Get-VcConnection -VcInstanceUuid '0b18a878-c2f9-40ac-b36d-efb68941cc52')
$_this.FindRulesForVm($vm)

#---------------CheckRelocate_Task---------------
$vm = New-Object VMware.Vim.ManagedObjectReference
$vm.Type = 'VirtualMachine'
$vm.Value = 'vm-109830'
$spec = New-Object VMware.Vim.VirtualMachineRelocateSpec
$spec.Disk = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator[] (2)
$spec.Disk[0] = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator
$spec.Disk[0].Datastore = New-Object VMware.Vim.ManagedObjectReference
$spec.Disk[0].Datastore.Type = 'Datastore'
$spec.Disk[0].Datastore.Value = 'datastore-2045'
$spec.Disk[0].DiskId = 2000
$spec.Disk[1] = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator
$spec.Disk[1].Datastore = New-Object VMware.Vim.ManagedObjectReference
$spec.Disk[1].Datastore.Type = 'Datastore'
$spec.Disk[1].Datastore.Value = 'datastore-2045'
$spec.Disk[1].DiskId = 2001
$spec.Folder = New-Object VMware.Vim.ManagedObjectReference
$spec.Folder.Type = 'Folder'
$spec.Folder.Value = 'group-v11385'
$spec.Datastore = New-Object VMware.Vim.ManagedObjectReference
$spec.Datastore.Type = 'Datastore'
$spec.Datastore.Value = 'datastore-2045'
$spec.DeviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec[] (1)
$spec.DeviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec
$spec.DeviceChange[0].Device = New-Object VMware.Vim.VirtualVmxnet3
$spec.DeviceChange[0].Device.MacAddress = '00:50:56:b3:ca:2f'
$spec.DeviceChange[0].Device.ResourceAllocation = New-Object VMware.Vim.VirtualEthernetCardResourceAllocation
$spec.DeviceChange[0].Device.ResourceAllocation.Limit = -1
$spec.DeviceChange[0].Device.ResourceAllocation.Reservation = 0
$spec.DeviceChange[0].Device.ResourceAllocation.Share = New-Object VMware.Vim.SharesInfo
$spec.DeviceChange[0].Device.ResourceAllocation.Share.Shares = 50
$spec.DeviceChange[0].Device.ResourceAllocation.Share.Level = 'normal'
$spec.DeviceChange[0].Device.Connectable = New-Object VMware.Vim.VirtualDeviceConnectInfo
$spec.DeviceChange[0].Device.Connectable.Connected = $true
$spec.DeviceChange[0].Device.Connectable.MigrateConnect = 'unset'
$spec.DeviceChange[0].Device.Connectable.AllowGuestControl = $true
$spec.DeviceChange[0].Device.Connectable.StartConnected = $true
$spec.DeviceChange[0].Device.Connectable.Status = 'ok'
$spec.DeviceChange[0].Device.Backing = New-Object VMware.Vim.VirtualEthernetCardDistributedVirtualPortBackingInfo
$spec.DeviceChange[0].Device.Backing.Port = New-Object VMware.Vim.DistributedVirtualSwitchPortConnection
$spec.DeviceChange[0].Device.Backing.Port.SwitchUuid = '50 0c d1 86 75 47 0a 57-3c c1 98 e3 6b 36 6e 03'
$spec.DeviceChange[0].Device.Backing.Port.PortgroupKey = 'dvportgroup-2085'
$spec.DeviceChange[0].Device.AddressType = 'assigned'
$spec.DeviceChange[0].Device.ControllerKey = 100
$spec.DeviceChange[0].Device.UnitNumber = 7
$spec.DeviceChange[0].Device.WakeOnLanEnabled = $true
$spec.DeviceChange[0].Device.SlotInfo = New-Object VMware.Vim.VirtualDevicePciBusSlotInfo
$spec.DeviceChange[0].Device.SlotInfo.PciSlotNumber = 192
$spec.DeviceChange[0].Device.UptCompatibilityEnabled = $true
$spec.DeviceChange[0].Device.DeviceInfo = New-Object VMware.Vim.Description
$spec.DeviceChange[0].Device.DeviceInfo.Summary = 'DVSwitch: 50 33 5b 75 f0 ae 7a c1-eb d5 6c 3c cb 7b 39 03'
$spec.DeviceChange[0].Device.DeviceInfo.Label = 'Network adapter 1'
$spec.DeviceChange[0].Device.Key = 4000
$spec.DeviceChange[0].Operation = 'edit'
$spec.Service = New-Object VMware.Vim.ServiceLocator
$spec.Service.Credential = New-Object VMware.Vim.ServiceLocatorSAMLCredential
$spec.Service.Credential.Token = 'Sensitive data is not recorded'
$spec.Service.SslThumbprint = 'F2:98:C3:B8:0C:46:87:76:13:88:D9:46:B1:B7:10:90:66:92:82:1E'
$spec.Service.InstanceUuid = '1bd6fbc3-30cd-4e97-be3b-48ca8bc30482'
$spec.Service.Url = 'https://DLC-VCSA.Prod-iNet.com:443/sdk'
$spec.Pool = New-Object VMware.Vim.ManagedObjectReference
$spec.Pool.Type = 'ResourcePool'
$spec.Pool.Value = 'resgroup-64'
$testType = New-Object String[] (5)
$testType[0] = 'sourceTests'
$testType[1] = 'resourcePoolTests'
$testType[2] = 'hostTests'
$testType[3] = 'networkTests'
$testType[4] = 'datastoreTests'
$_this = Get-View -Id 'VirtualMachineProvisioningChecker-ProvChecker' -Server (Get-VcConnection -VcInstanceUuid '0b18a878-c2f9-40ac-b36d-efb68941cc52')
$_this.CheckRelocate_Task($vm, $spec, $testType)
#>
    # Issue Cross VC-vMotion
    $task = $vm_view.RelocateVM_Task($spec,"defaultPriority")
    $task1 = Get-Task -Id ("Task-$($task.value)")
    $task1 | Wait-Task
}

# Variables that must be defined

$vmname = "TinyVM-2"
$sourceVC = "vcenter60-1.primp-industries.com"
$sourceVCUsername = "administrator@vghetto.local"
$sourceVCPassword = "VMware1!"
$destVC = "vcenter60-3.primp-industries.com"
$destVCUsername = "administrator@vghetto.local"
$destVCpassword = "VMware1!"
$datastorename = "la-datastore1"
$resourcepool = "WorkloadRP"
$vmhostname = "vesxi60-5.primp-industries.com"
$vmnetworkname = "LA-VM-Network1,LA-VM-Network2"
$switchname = "LA-VDS"
$switchtype = "vds"
$ComputeXVC = 1
$UppercaseUUID = $false

# Connect to Source/Destination vCenter Server
$sourceVCConn = Connect-VIServer -Server $sourceVC -user $sourceVCUsername -password $sourceVCPassword
$destVCConn = Connect-VIServer -Server $destVC -user $destVCUsername -password $destVCpassword

xMove-VM -sourcevc $sourceVCConn -destvc $destVCConn -VM $vmname -switchtype $switchtype -switch $switchname -resourcepool $resourcepool -vmhost $vmhostname -datastore $datastorename -vmnetwork  $vmnetworkname -xvcType $computeXVC -uppercaseuuid $UppercaseUUID

# Disconnect from Source/Destination VC
Disconnect-VIServer -Server $sourceVCConn -Confirm:$false
Disconnect-VIServer -Server $destVCConn -Confirm:$false
<#
#---------------RelocateVM_Task---------------
$spec = New-Object VMware.Vim.VirtualMachineRelocateSpec
$spec.Disk = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator[] (2)
$spec.Disk[0] = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator
$spec.Disk[0].DiskMoveType = 'moveAllDiskBackingsAndDisallowSharing'
$spec.Disk[0].Datastore = New-Object VMware.Vim.ManagedObjectReference
$spec.Disk[0].Datastore.Type = 'Datastore'
$spec.Disk[0].Datastore.Value = 'datastore-2045'
$spec.Disk[0].DiskId = 2000
$spec.Disk[1] = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator
$spec.Disk[1].DiskMoveType = 'moveAllDiskBackingsAndDisallowSharing'
$spec.Disk[1].Datastore = New-Object VMware.Vim.ManagedObjectReference
$spec.Disk[1].Datastore.Type = 'Datastore'
$spec.Disk[1].Datastore.Value = 'datastore-2045'
$spec.Disk[1].DiskId = 2001
$spec.Folder = New-Object VMware.Vim.ManagedObjectReference
$spec.Folder.Type = 'Folder'
$spec.Folder.Value = 'group-v11385'
$spec.Datastore = New-Object VMware.Vim.ManagedObjectReference
$spec.Datastore.Type = 'Datastore'
$spec.Datastore.Value = 'datastore-2045'
$spec.DeviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec[] (1)
$spec.DeviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec
$spec.DeviceChange[0].Device = New-Object VMware.Vim.VirtualVmxnet3
$spec.DeviceChange[0].Device.MacAddress = '00:50:56:b3:ca:2f'
$spec.DeviceChange[0].Device.ResourceAllocation = New-Object VMware.Vim.VirtualEthernetCardResourceAllocation
$spec.DeviceChange[0].Device.ResourceAllocation.Limit = -1
$spec.DeviceChange[0].Device.ResourceAllocation.Reservation = 0
$spec.DeviceChange[0].Device.ResourceAllocation.Share = New-Object VMware.Vim.SharesInfo
$spec.DeviceChange[0].Device.ResourceAllocation.Share.Shares = 50
$spec.DeviceChange[0].Device.ResourceAllocation.Share.Level = 'normal'
$spec.DeviceChange[0].Device.Connectable = New-Object VMware.Vim.VirtualDeviceConnectInfo
$spec.DeviceChange[0].Device.Connectable.Connected = $true
$spec.DeviceChange[0].Device.Connectable.MigrateConnect = 'unset'
$spec.DeviceChange[0].Device.Connectable.AllowGuestControl = $true
$spec.DeviceChange[0].Device.Connectable.StartConnected = $true
$spec.DeviceChange[0].Device.Connectable.Status = 'ok'
$spec.DeviceChange[0].Device.Backing = New-Object VMware.Vim.VirtualEthernetCardDistributedVirtualPortBackingInfo
$spec.DeviceChange[0].Device.Backing.Port = New-Object VMware.Vim.DistributedVirtualSwitchPortConnection
$spec.DeviceChange[0].Device.Backing.Port.SwitchUuid = '50 0c d1 86 75 47 0a 57-3c c1 98 e3 6b 36 6e 03'
$spec.DeviceChange[0].Device.Backing.Port.PortgroupKey = 'dvportgroup-2085'
$spec.DeviceChange[0].Device.AddressType = 'assigned'
$spec.DeviceChange[0].Device.ControllerKey = 100
$spec.DeviceChange[0].Device.UnitNumber = 7
$spec.DeviceChange[0].Device.WakeOnLanEnabled = $true
$spec.DeviceChange[0].Device.SlotInfo = New-Object VMware.Vim.VirtualDevicePciBusSlotInfo
$spec.DeviceChange[0].Device.SlotInfo.PciSlotNumber = 192
$spec.DeviceChange[0].Device.UptCompatibilityEnabled = $true
$spec.DeviceChange[0].Device.DeviceInfo = New-Object VMware.Vim.Description
$spec.DeviceChange[0].Device.DeviceInfo.Summary = 'DVSwitch: 50 33 5b 75 f0 ae 7a c1-eb d5 6c 3c cb 7b 39 03'
$spec.DeviceChange[0].Device.DeviceInfo.Label = 'Network adapter 1'
$spec.DeviceChange[0].Device.Key = 4000
$spec.DeviceChange[0].Operation = 'edit'
$spec.Service = New-Object VMware.Vim.ServiceLocator
$spec.Service.Credential = New-Object VMware.Vim.ServiceLocatorSAMLCredential
$spec.Service.Credential.Token = 'Sensitive data is not recorded'
$spec.Service.SslThumbprint = 'F2:98:C3:B8:0C:46:87:76:13:88:D9:46:B1:B7:10:90:66:92:82:1E'
$spec.Service.InstanceUuid = '1bd6fbc3-30cd-4e97-be3b-48ca8bc30482'
$spec.Service.Url = 'https://DLC-VCSA.Prod-iNet.com:443/sdk'
$spec.Host = New-Object VMware.Vim.ManagedObjectReference
$spec.Host.Type = 'HostSystem'
$spec.Host.Value = 'host-4003'
$spec.Pool = New-Object VMware.Vim.ManagedObjectReference
$spec.Pool.Type = 'ResourcePool'
$spec.Pool.Value = 'resgroup-64'
$priority = 'lowPriority'
$_this = Get-View -Id 'VirtualMachine-vm-109830' -Server (Get-VcConnection -VcInstanceUuid '0b18a878-c2f9-40ac-b36d-efb68941cc52')
$_this.RelocateVM_Task($spec, $priority)
#>